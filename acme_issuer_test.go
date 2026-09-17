package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestCloudflareTokenFile(t *testing.T) {
	var output bytes.Buffer
	logger := zerolog.New(&output)
	oldLog, oldLevel := log, zerolog.GlobalLevel()
	log = &logger
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { log = oldLog; zerolog.SetGlobalLevel(oldLevel) })
	for _, tt := range []struct {
		name                 string
		mode                 os.FileMode
		contents             string
		wantWarning, wantErr bool
	}{
		{name: "private token file", mode: 0600, contents: "  test-token\n"},
		{name: "group readable", mode: 0640, contents: "test-token", wantWarning: true},
		{name: "world readable", mode: 0644, contents: "test-token", wantWarning: true},
		{name: "owner read only", mode: 0400, contents: "test-token", wantWarning: true},
		{name: "empty file", mode: 0600, contents: " \n", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			output.Reset()
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(tt.contents), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatal(err)
			}
			config, err := cloudflareTokenConfig(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("token file error = %v", err)
			}
			if !tt.wantErr && (config.AuthToken != "test-token" || config.ZoneToken != "test-token") {
				t.Fatal("file token was not supplied for both Cloudflare permissions")
			}
			if tt.wantWarning {
				var entry struct{ Level, File, Permissions string }
				if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
					t.Fatal(err)
				}
				if entry.Level != "warn" || entry.File != path || entry.Permissions == "" {
					t.Fatal("missing file permission warning")
				}
			} else if output.Len() != 0 {
				t.Fatalf("unexpected log: %s", output.String())
			}
			if strings.Contains(output.String(), "test-token") {
				t.Fatal("token leaked into logs")
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		if _, err := cloudflareTokenConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("missing file accepted")
		}
	})
	t.Run("read updated token", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		for _, token := range []string{"first-token", "second-token"} {
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			config, err := cloudflareTokenConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if config.AuthToken != token || config.ZoneToken != token {
				t.Fatal("updated token was not read")
			}
		}
	})
}

// Exercise the real lego integration against a local ACME server. Authorization
// is already valid, so this test neither accesses Cloudflare nor public DNS.
func TestLegoIssuanceAccountReuseAndKeyRotation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	var accounts, orders, replacements atomic.Int32
	var serial atomic.Int64
	var bundle atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverURL := "https://" + r.Host
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(time.Now().String())))
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		payload := func(v any) bool {
			var jws struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Error(err)
				return false
			}
			data, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err != nil {
				t.Error(err)
				return false
			}
			if err := json.Unmarshal(data, v); err != nil {
				t.Error(err)
				return false
			}
			return true
		}
		switch {
		case r.URL.Path == "/directory":
			write(map[string]string{"newNonce": serverURL + "/nonce", "newAccount": serverURL + "/account", "newOrder": serverURL + "/order", "renewalInfo": serverURL + "/renewal-info"})
		case r.URL.Path == "/nonce":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/account":
			accounts.Add(1)
			w.Header().Set("Location", serverURL+"/accounts/1")
			w.WriteHeader(http.StatusCreated)
			write(map[string]string{"status": "valid"})
		case r.URL.Path == "/order":
			var order map[string]any
			if !payload(&order) {
				return
			}
			orders.Add(1)
			if value, _ := order["replaces"].(string); value != "" {
				replacements.Add(1)
			}
			order["status"], order["finalize"], order["authorizations"] = "ready", serverURL+"/finalize", []string{serverURL + "/auth"}
			w.Header().Set("Location", serverURL+"/orders/1")
			w.WriteHeader(http.StatusCreated)
			write(order)
		case r.URL.Path == "/auth":
			write(map[string]any{"status": "valid", "identifier": map[string]string{"type": "dns", "value": "smtp.example.com"}})
		case r.URL.Path == "/finalize":
			var request struct {
				CSR string `json:"csr"`
			}
			if !payload(&request) {
				return
			}
			der, err := base64.RawURLEncoding.DecodeString(request.CSR)
			if err != nil {
				t.Error(err)
				return
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Error(err)
				return
			}
			if err := csr.CheckSignature(); err != nil {
				t.Error(err)
				return
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1) + 1), DNSNames: csr.DNSNames,
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
			leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, csr.PublicKey, key)
			if err != nil {
				t.Error(err)
				return
			}
			bundle.Store(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...))
			write(map[string]string{"status": "valid", "certificate": serverURL + "/certificate"})
		case r.URL.Path == "/certificate":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(bundle.Load().([]byte))
		case strings.HasPrefix(r.URL.Path, "/renewal-info/"):
			write(map[string]any{"suggestedWindow": map[string]time.Time{"start": now.Add(24 * time.Hour), "end": now.Add(48 * time.Hour)}})
		default:
			t.Errorf("unexpected ACME request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	trustTestACMEServer(t, server)
	opts := acmeOptions{Domains: []string{"smtp.example.com"}, Storage: t.TempDir(), Directory: server.URL + "/directory"}
	opts.CFTokenFile = filepath.Join(t.TempDir(), "cloudflare-token")
	if err := os.WriteFile(opts.CFTokenFile, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issuer := &legoIssuer{opts: opts}
	first, err := issuer.Obtain(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseACMECertificate(first, opts.Domains, now)
	if err != nil {
		t.Fatal(err)
	}
	due, err := issuer.RenewalTime(context.Background(), cert.Leaf, now)
	if err != nil || due.Before(now.Add(24*time.Hour)) || due.After(now.Add(48*time.Hour)) {
		t.Fatalf("ARI time = %s, err = %v", due, err)
	}
	second, err := (&legoIssuer{opts: opts}).Obtain(context.Background(), first.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseACMECertificate(second, opts.Domains, now); err != nil {
		t.Fatal(err)
	}
	if accounts.Load() != 1 || orders.Load() != 2 || replacements.Load() != 1 {
		t.Fatalf("accounts/orders/replacements = %d/%d/%d", accounts.Load(), orders.Load(), replacements.Load())
	}
	if bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatal("certificate private key was reused")
	}
}

func TestLegoDirectoryDiscoveryCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	trustTestACMEServer(t, server)
	issuer := &legoIssuer{opts: acmeOptions{Storage: t.TempDir(), Directory: server.URL}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := issuer.client(ctx); err == nil {
		t.Fatal("directory request ignored cancellation")
	}
}

func trustTestACMEServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", path)
}

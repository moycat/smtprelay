package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/registration"
)

type acmeAccount struct {
	Email        string                `json:"email"`
	Directory    string                `json:"directory"`
	Key          []byte                `json:"key"`
	Registration *acme.ExtendedAccount `json:"registration,omitempty"`
	privateKey   crypto.Signer
}

func (a *acmeAccount) GetEmail() string                       { return a.Email }
func (a *acmeAccount) GetRegistration() *acme.ExtendedAccount { return a.Registration }
func (a *acmeAccount) GetPrivateKey() crypto.Signer           { return a.privateKey }

type legoIssuer struct{ opts acmeOptions }

// Also applies cancellation to directory discovery, which lego performs while
// constructing the client, before its context-aware methods can be called.
type acmeTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t acmeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r.Clone(t.ctx))
}

func (l *legoIssuer) client(ctx context.Context) (*lego.Client, error) {
	path := filepath.Join(l.opts.Storage, "account.json")
	account := &acmeAccount{}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, account); err != nil {
			return nil, fmt.Errorf("read ACME account: %w", err)
		}
		key, err := certcrypto.ParsePEMPrivateKey(account.Key)
		if err != nil {
			return nil, fmt.Errorf("read ACME account key: %w", err)
		}
		account.privateKey = key
	} else if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		account.privateKey = key
		account.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		return nil, err
	}
	if account.Directory != l.opts.Directory {
		account.Registration = nil
	}
	account.Email, account.Directory = l.opts.Email, l.opts.Directory
	if account.Registration == nil {
		// Persist the account key before registration so retries reuse it.
		if err := writeACMEJSON(path, account); err != nil {
			return nil, err
		}
	}
	config := lego.NewConfig(account)
	config.CADirURL = l.opts.Directory
	config.UserAgent = "smtprelay/" + appVersion
	config.HTTPClient.Timeout = 30 * time.Second
	base := config.HTTPClient.Transport.(*http.Transport)
	base.IdleConnTimeout = 30 * time.Second
	config.HTTPClient.Transport = acmeTransport{ctx: ctx, base: base}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	if account.Registration == nil {
		account.Registration, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		if err := writeACMEJSON(path, account); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (l *legoIssuer) Obtain(ctx context.Context, previous []byte) (acmeCertificateState, error) {
	var result acmeCertificateState
	config, err := cloudflareTokenConfig(l.opts.CFTokenFile)
	if err != nil {
		return result, err
	}
	provider, err := cloudflare.NewDNSProviderConfig(config)
	if err != nil {
		return result, fmt.Errorf("configure Cloudflare DNS: %w", err)
	}
	client, err := l.client(ctx)
	if err != nil {
		return result, err
	}
	if err := client.Challenge.SetDNS01Provider(provider, dns01.DisableRecursiveNSsPropagationRequirement()); err != nil {
		return result, err
	}
	request := certificate.ObtainRequest{Domains: l.opts.Domains, Bundle: true, KeyType: certcrypto.RSA2048}
	// Identify a replacement to the CA when ARI is supported. Obtain generates
	// a fresh certificate key; the separate account key remains unchanged.
	if certificates, err := certcrypto.ParsePEMBundle(previous); err == nil && len(certificates) > 0 {
		if _, err := client.Certificate.GetRenewalInfo(ctx, certificates[0]); err == nil {
			request.ReplacesCertID, _ = api.MakeARICertID(certificates[0])
		}
	}
	cert, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		return result, fmt.Errorf("request ACME certificate: %w", err)
	}
	result.Certificate, result.PrivateKey = cert.Certificate, cert.PrivateKey
	return result, nil
}

func cloudflareTokenConfig(path string) (*cloudflare.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Cloudflare token file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Cloudflare token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Cloudflare token file must be a regular file")
	}
	if info.Mode().Perm() != 0600 {
		log.Warn().Str("file", path).Str("permissions", fmt.Sprintf("%04o", info.Mode().Perm())).
			Msg("Cloudflare token file permissions should be 0600")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read Cloudflare token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("Cloudflare token file is empty")
	}
	config := cloudflare.NewDefaultConfig()
	config.AuthToken, config.ZoneToken = token, token
	return config, nil
}

func (l *legoIssuer) RenewalTime(ctx context.Context, cert *x509.Certificate, now time.Time) (time.Time, error) {
	client, err := l.client(ctx)
	if err != nil {
		return time.Time{}, err
	}
	info, err := client.Certificate.GetRenewalInfo(ctx, cert)
	if err != nil {
		return time.Time{}, err
	}
	if due := info.ShouldRenewAt(now, cert.NotAfter.Sub(now)); due != nil {
		return *due, nil
	}
	return time.Time{}, nil
}

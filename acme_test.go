package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chrj/smtpd"
)

type testACMEIssuer struct {
	result acmeCertificateState
	err    error
	ari    time.Time
	ariErr error
	calls  int
}

func (i *testACMEIssuer) Obtain(context.Context, []byte) (acmeCertificateState, error) {
	i.calls++
	return i.result, i.err
}

func (i *testACMEIssuer) RenewalTime(context.Context, *x509.Certificate, time.Time) (time.Time, error) {
	return i.ari, i.ariErr
}

func testACMECertificate(t *testing.T, serial int64, domain string, start, end time.Time) acmeCertificateState {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), DNSNames: []string{domain},
		NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return acmeCertificateState{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func testACMEManager(t *testing.T, cached acmeCertificateState, issuer acmeIssuer) *acmeManager {
	t.Helper()
	opts := acmeOptions{Domains: []string{"smtp.example.com"}, Storage: t.TempDir()}
	if cached.Certificate != nil {
		if err := writeACMEJSON(filepath.Join(opts.Storage, "certificate.json"), cached); err != nil {
			t.Fatal(err)
		}
	}
	m, err := newACMEManager(opts, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestACMEFailureRetryAndRestart(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	old := testACMECertificate(t, 1, "smtp.example.com", now.Add(-70*24*time.Hour), now.Add(20*24*time.Hour))
	issuer := &testACMEIssuer{err: errors.New("DNS unavailable")}
	m := testACMEManager(t, old, issuer)
	m.now = func() time.Time { return now }
	notifications := 0
	m.notify = func(_ context.Context, retry time.Time) {
		notifications++
		if !retry.Equal(now.Add(24 * time.Hour)) {
			t.Errorf("retry = %v", retry)
		}
	}
	path := filepath.Join(m.opts.Storage, "certificate.json")
	before, _ := os.ReadFile(path)
	if delay := m.step(context.Background()); delay != 24*time.Hour {
		t.Fatalf("delay = %s", delay)
	}
	cert, err := m.GetCertificate(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("old certificate unavailable: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed attempt changed disk state")
	}

	now = now.Add(23 * time.Hour)
	if delay := m.step(context.Background()); delay != time.Hour {
		t.Fatalf("delay = %s", delay)
	}
	if issuer.calls != 1 || notifications != 1 {
		t.Fatal("retried or notified before 24 hours")
	}
	now = now.Add(time.Hour)
	m.step(context.Background())
	if issuer.calls != 2 || notifications != 2 {
		t.Fatal("did not retry and notify after 24 hours")
	}

	// Restart forgets the retry timer and immediately retries a due certificate.
	restarted, err := newACMEManager(m.opts, issuer)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = m.now
	restarted.step(context.Background())
	if issuer.calls != 3 {
		t.Fatal("restart incorrectly restored retry state")
	}

	now = now.Add(24 * time.Hour)
	issuer.err = nil
	issuer.result = testACMECertificate(t, 2, "smtp.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	m.step(context.Background())
	cert, err = m.GetCertificate(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("renewed certificate not loaded: %v", err)
	}
	if notifications != 2 || !m.retryAt.IsZero() {
		t.Fatal("success should clear retry state without a failure notification")
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("certificate file permissions: %v, %v", stat, err)
	}
}

func TestACMERenewalScheduling(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, tt := range []struct {
		name      string
		age, life time.Duration
		ari       time.Time
		ariErr    error
		wantCalls int
	}{
		{name: "not due", age: 10 * 24 * time.Hour, life: 90 * 24 * time.Hour},
		{name: "normal threshold", age: 60 * 24 * time.Hour, life: 90 * 24 * time.Hour, wantCalls: 1},
		{name: "short lived threshold", age: 3 * 24 * time.Hour, life: 6 * 24 * time.Hour, wantCalls: 1},
		{name: "ARI requests early renewal", age: 10 * 24 * time.Hour, life: 90 * 24 * time.Hour, ari: now, wantCalls: 1},
		{name: "ARI unavailable", age: 10 * 24 * time.Hour, life: 90 * 24 * time.Hour, ariErr: errors.New("offline")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := testACMECertificate(t, 1, "smtp.example.com", now.Add(-tt.age), now.Add(tt.life-tt.age))
			issuer := &testACMEIssuer{ari: tt.ari, ariErr: tt.ariErr, err: errors.New("test issuance failure")}
			m := testACMEManager(t, old, issuer)
			m.now = func() time.Time { return now }
			m.step(context.Background())
			if issuer.calls != tt.wantCalls {
				t.Fatalf("issuance calls = %d, want %d", issuer.calls, tt.wantCalls)
			}
		})
	}
	t.Run("scheduled ARI time is honored", func(t *testing.T) {
		old := testACMECertificate(t, 1, "smtp.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
		issuer := &testACMEIssuer{ari: now.Add(10 * time.Minute), err: errors.New("test")}
		m := testACMEManager(t, old, issuer)
		m.now = func() time.Time { return now }
		if delay := m.step(context.Background()); delay != 10*time.Minute {
			t.Fatalf("delay = %s", delay)
		}
		now = now.Add(10 * time.Minute)
		issuer.ari = now.Add(time.Hour)
		m.step(context.Background())
		if issuer.calls != 1 {
			t.Fatal("resampling ARI postponed a scheduled renewal")
		}
	})
}

func TestACMERejectsBadReplacement(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	old := testACMECertificate(t, 1, "smtp.example.com", now.Add(-70*24*time.Hour), now.Add(20*24*time.Hour))
	valid := testACMECertificate(t, 2, "smtp.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, tt := range []struct {
		name        string
		result      acmeCertificateState
		diskFailure bool
	}{
		{name: "wrong domain", result: testACMECertificate(t, 2, "other.example.com", now.Add(-time.Hour), now.Add(time.Hour))},
		{name: "expired", result: testACMECertificate(t, 2, "smtp.example.com", now.Add(-2*time.Hour), now.Add(-time.Hour))},
		{name: "not yet valid", result: testACMECertificate(t, 2, "smtp.example.com", now.Add(time.Hour), now.Add(2*time.Hour))},
		{name: "mismatched key", result: acmeCertificateState{Certificate: valid.Certificate, PrivateKey: old.PrivateKey}},
		{name: "disk failure", result: valid, diskFailure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := testACMEManager(t, old, &testACMEIssuer{result: tt.result})
			if tt.diskFailure {
				m.opts.Storage = filepath.Join(m.opts.Storage, "missing")
			}
			alerts := 0
			m.notify = func(context.Context, time.Time) { alerts++ }
			m.step(context.Background())
			cert, err := m.GetCertificate(nil)
			if err != nil || cert.Leaf.SerialNumber.Int64() != 1 || alerts != 1 {
				t.Fatalf("old certificate not preserved or alert missing: %v", err)
			}
		})
	}
}

func TestACMEExpiryAndInitialReadiness(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	issuer := &testACMEIssuer{err: errors.New("offline")}
	m := testACMEManager(t, acmeCertificateState{}, issuer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(m.WaitReady(ctx), context.Canceled) {
		t.Fatal("startup wait ignored cancellation")
	}
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("served TLS before a certificate was available")
	}
	issuer.err = nil
	issuer.result = testACMECertificate(t, 1, "smtp.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	m.step(context.Background())
	if err := m.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now.Add(91 * 24 * time.Hour) }
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("served an expired certificate")
	}
}

func startTestSMTP(t *testing.T, config *tls.Config, implicitTLS bool, handler func(smtpd.Peer, smtpd.Envelope) error) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicitTLS {
		listener = tls.NewListener(listener, config)
	}
	server := &smtpd.Server{Hostname: "smtp.example.com", TLSConfig: config, Handler: handler, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close(); <-done; _ = server.Shutdown(true) })
	return listener.Addr().String()
}

func TestACMEHotReloadSMTPSAndSTARTTLS(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	old := testACMECertificate(t, 1, "smtp.example.com", now.Add(-70*24*time.Hour), now.Add(20*24*time.Hour))
	newCert := testACMECertificate(t, 2, "smtp.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	m := testACMEManager(t, old, &testACMEIssuer{result: newCert})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(old.Certificate)
	pool.AppendCertsFromPEM(newCert.Certificate)
	addresses := []string{
		startTestSMTP(t, getTLSConfig(m), true, nil),
		startTestSMTP(t, getTLSConfig(m), false, nil),
	}
	connect := func(index int, sni bool, serial int64) *Client {
		t.Helper()
		config := &tls.Config{RootCAs: pool, ServerName: "smtp.example.com"}
		if !sni {
			// Verify normally, but omit SNI to reproduce legacy SMTP clients.
			config.ServerName, config.InsecureSkipVerify = "", true
			config.VerifyConnection = func(state tls.ConnectionState) error {
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: "smtp.example.com"})
				return err
			}
		}
		conn, err := net.DialTimeout("tcp", addresses[index], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var wire net.Conn = conn
		if index == 0 {
			wire = tls.Client(conn, config)
		}
		client, err := NewClient(wire, "smtp.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if index == 1 {
			if err := client.StartTLS(config); err != nil {
				t.Fatal(err)
			}
		}
		state, ok := client.TLSConnectionState()
		if !ok || state.PeerCertificates[0].SerialNumber.Int64() != serial {
			t.Fatal("wrong certificate on SMTP connection")
		}
		return client
	}
	var existing []*Client
	for i := range addresses {
		for _, sni := range []bool{true, false} {
			existing = append(existing, connect(i, sni, 1))
		}
	}
	m.step(context.Background())
	for i := range addresses {
		for _, sni := range []bool{true, false} {
			client := connect(i, sni, 2)
			_ = client.Quit()
		}
	}
	for _, client := range existing {
		if err := client.Noop(); err != nil {
			t.Fatalf("rotation broke existing connection: %v", err)
		}
		_ = client.Quit()
	}
}

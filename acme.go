package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const acmeRetryInterval = 24 * time.Hour

type acmeOptions struct {
	Domains                   []string
	Email, Directory, Storage string
	CFTokenFile               string
	NotifyFrom                string
	NotifyTo                  []string
}

func loadACMEOptions() (acmeOptions, error) {
	opts := acmeOptions{
		Email: *acmeEmail, Directory: *acmeDirectory, Storage: *acmeStorage,
		CFTokenFile: *acmeCFTokenFile,
		NotifyFrom:  *acmeNotifyFrom,
	}
	for _, domain := range strings.FieldsFunc(*acmeDomains, func(r rune) bool { return r == ',' || r == ' ' }) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if !validACMEDomain(domain) {
			return opts, fmt.Errorf("invalid acme_domains DNS name: %q", domain)
		}
		if !slices.Contains(opts.Domains, domain) {
			opts.Domains = append(opts.Domains, domain)
		}
	}
	if len(opts.Domains) == 0 || opts.Storage == "" || opts.CFTokenFile == "" {
		return opts, errors.New("acme_domains, acme_storage and acme_cf_token_file must be set")
	}
	u, err := url.Parse(opts.Directory)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return opts, errors.New("acme_directory must be an HTTPS URL without credentials")
	}
	if opts.Email != "" {
		if err := validateMailbox(opts.Email); err != nil {
			return opts, fmt.Errorf("acme_email: %w", err)
		}
	}
	if *acmeNotifyTo != "" {
		addresses, err := mail.ParseAddressList(*acmeNotifyTo)
		if err != nil || len(addresses) == 0 || strings.ContainsAny(*acmeNotifyTo, "\r\n") {
			return opts, errors.New("acme_notify_to must contain valid email addresses")
		}
		for _, address := range addresses {
			opts.NotifyTo = append(opts.NotifyTo, address.Address)
		}
		if err := validateMailbox(opts.NotifyFrom); err != nil {
			return opts, fmt.Errorf("acme_notify_from: %w", err)
		}
		if len(remotes) == 0 {
			return opts, errors.New("ACME email notifications require at least one remote")
		}
	}
	return opts, nil
}

func validateMailbox(value string) error {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || strings.ContainsAny(value, "\r\n") {
		return errors.New("expected a single mailbox address without a display name")
	}
	return nil
}

func validACMEDomain(domain string) bool {
	domain = strings.TrimPrefix(domain, "*.")
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Keep the chain and its private key in one atomically replaced file.
type acmeCertificateState struct {
	Certificate []byte `json:"certificate,omitempty"`
	PrivateKey  []byte `json:"private_key,omitempty"`
}

type acmeIssuer interface {
	Obtain(context.Context, []byte) (acmeCertificateState, error)
	RenewalTime(context.Context, *x509.Certificate, time.Time) (time.Time, error)
}

type acmeManager struct {
	opts      acmeOptions
	issuer    acmeIssuer
	state     acmeCertificateState // only the maintenance goroutine writes state
	retryAt   time.Time            // failed attempts wait 24 hours; reset on restart
	renewAt   time.Time
	current   atomic.Pointer[tls.Certificate]
	ready     chan struct{}
	readyOnce sync.Once
	notify    func(context.Context, time.Time)
	now       func() time.Time
}

func newACMEManager(opts acmeOptions, issuer acmeIssuer) (*acmeManager, error) {
	if err := os.MkdirAll(opts.Storage, 0700); err != nil {
		return nil, err
	}
	m := &acmeManager{opts: opts, issuer: issuer, ready: make(chan struct{}), now: time.Now}
	data, err := os.ReadFile(filepath.Join(opts.Storage, "certificate.json"))
	if err == nil {
		if err := json.Unmarshal(data, &m.state); err != nil {
			return nil, fmt.Errorf("read cached ACME certificate: %w", err)
		}
		if len(m.state.Certificate) > 0 {
			cert, err := parseACMECertificate(m.state, opts.Domains, m.now())
			if err == nil {
				m.publish(cert)
			} else {
				log.Warn().Err(err).Msg("cached ACME certificate is unusable; waiting for issuance")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

func (m *acmeManager) publish(cert *tls.Certificate) {
	m.current.Store(cert)
	m.readyOnce.Do(func() { close(m.ready) })
}

func (m *acmeManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := m.current.Load()
	if cert == nil || m.now().Before(cert.Leaf.NotBefore) || !m.now().Before(cert.Leaf.NotAfter) {
		return nil, errors.New("no valid ACME certificate available")
	}
	return cert, nil
}

func (m *acmeManager) WaitReady(ctx context.Context) error {
	select {
	case <-m.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *acmeManager) Run(ctx context.Context) {
	for ctx.Err() == nil {
		delay := m.step(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *acmeManager) step(ctx context.Context) time.Duration {
	now := m.now()
	if now.Before(m.retryAt) {
		return m.retryAt.Sub(now)
	}
	if cert := m.current.Load(); cert != nil && m.retryAt.IsZero() {
		due := fallbackRenewalTime(cert.Leaf)
		if !m.renewAt.IsZero() {
			due = m.renewAt
		}
		if now.Before(due) {
			checkCtx, cancel := context.WithTimeout(ctx, time.Minute)
			ari, err := m.issuer.RenewalTime(checkCtx, cert.Leaf, now)
			cancel()
			if err == nil && !ari.IsZero() && ari.Before(cert.Leaf.NotAfter) {
				due = ari
			}
			m.renewAt = due
			if now.Before(due) {
				return min(time.Hour, due.Sub(now))
			}
		}
	}

	attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	next, err := m.issuer.Obtain(attemptCtx, m.state.Certificate)
	cancel()
	if ctx.Err() != nil {
		return 0
	}
	var cert *tls.Certificate
	if err == nil {
		cert, err = parseACMECertificate(next, m.opts.Domains, m.now())
	}
	if err == nil {
		err = writeACMEJSON(filepath.Join(m.opts.Storage, "certificate.json"), next)
	}
	if err != nil {
		m.retryAt = m.now().Add(acmeRetryInterval)
		log.Error().Err(err).Time("retry_at", m.retryAt).Msg("ACME issuance failed")
		if m.notify != nil {
			// The SMTP delivery has its own timeout and does not use local listeners.
			m.notify(ctx, m.retryAt)
		}
		return max(0, m.retryAt.Sub(m.now()))
	}
	m.retryAt = time.Time{}
	m.renewAt = time.Time{}
	m.state = next
	m.publish(cert)
	log.Info().Strs("domains", m.opts.Domains).Time("expires", cert.Leaf.NotAfter).Msg("ACME certificate loaded")
	return min(time.Hour, max(0, fallbackRenewalTime(cert.Leaf).Sub(m.now())))
}

func fallbackRenewalTime(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime <= 10*24*time.Hour {
		return cert.NotBefore.Add(lifetime / 2)
	}
	return cert.NotBefore.Add(lifetime * 2 / 3)
}

func parseACMECertificate(state acmeCertificateState, domains []string, now time.Time) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(state.Certificate, state.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load ACME certificate/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("ACME certificate is not a currently valid server certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("ACME certificate does not permit server authentication")
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			if !slices.Contains(leaf.DNSNames, domain) {
				return nil, fmt.Errorf("ACME certificate is missing %s", domain)
			}
		} else if err := leaf.VerifyHostname(domain); err != nil {
			return nil, err
		}
	}
	child := leaf
	for _, der := range cert.Certificate[1:] {
		parent, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return nil, fmt.Errorf("invalid ACME certificate chain: %w", err)
		}
		child = parent
	}
	cert.Leaf = leaf
	return &cert, nil
}

func writeACMEJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".acme-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

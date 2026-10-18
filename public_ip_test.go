package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsPublicRelayIP(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		t.Run(value, func(t *testing.T) {
			if !isPublicRelayIP(netip.MustParseAddr(value)) {
				t.Fatalf("ordinary public address %s was rejected", value)
			}
		})
	}
	for _, value := range []string{
		"0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1",
		"169.254.1.1", "172.16.0.1", "172.31.255.254", "192.0.0.9", "192.0.2.1",
		"192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1",
		"198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1",
		"239.255.255.254", "240.0.0.1", "255.255.255.255", "::", "::1", "::8.8.8.8",
		"::ffff:192.168.1.1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:1::1", "2001:2::1", "2001:3::1", "2001:4:112::1", "2001:20::1",
		"2001:db8::1", "2002:808:808::1", "2620:4f:8000::1", "3fff::1", "5f00::1",
		"fc00::1", "fd12::1", "fe80::1", "fec0::1", "ff02::1", "4000::1", "8000::1",
		"2606:4700:4700::1111%eth0",
	} {
		t.Run(value, func(t *testing.T) {
			if isPublicRelayIP(netip.MustParseAddr(value)) {
				t.Fatalf("special or non-public address %s was accepted", value)
			}
		})
	}
	if isPublicRelayIP(netip.Addr{}) {
		t.Fatal("invalid address was accepted")
	}
}

func TestResolveRelayPublicIPConfigured(t *testing.T) {
	// Explicit configuration needs no discovery, even with a canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct{ configured, want string }{
		{"8.8.8.8", "8.8.8.8"},
		{" 2606:4700:4700::1111 ", "2606:4700:4700::1111"},
		{"::ffff:8.8.8.8", "8.8.8.8"},
	} {
		got, err := resolveRelayPublicIP(ctx, test.configured)
		if err != nil || got.String() != test.want {
			t.Errorf("resolve(%q) = %v, %v; want %s", test.configured, got, err, test.want)
		}
	}
	for _, value := range []string{"smtp.example.com", "8.8.8.8:25", "https://8.8.8.8", "192.168.1.1", "100.64.0.1", "2001:db8::1", "2606:4700:4700::1111%eth0"} {
		got, err := resolveRelayPublicIP(ctx, value)
		if err == nil || got.IsValid() {
			t.Errorf("resolve(%q) = %v, %v; want invalid address and error", value, got, err)
		}
	}
}

func TestRelayPublicIPClientPolicy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client := newRelayPublicIPClient()
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("public IP discovery must not use environment proxies")
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("HTTP timeout = %v, want 5 seconds", client.Timeout)
	}
}

func TestQueryRelayPublicIP(t *testing.T) {
	for _, test := range []struct {
		name, body, want string
		status           int
	}{
		{name: "IPv4", body: "8.8.8.8\n", want: "8.8.8.8"},
		{name: "IPv6", body: "2606:4700:4700::1111", want: "2606:4700:4700::1111"},
		{name: "mapped IPv4", body: "::ffff:8.8.8.8", want: "8.8.8.8"},
		{name: "maximum body", body: "8.8.8.8" + strings.Repeat(" ", relayPublicIPMaxBody-7), want: "8.8.8.8"},
		{name: "private", body: "10.0.0.1"},
		{name: "documentation", body: "2001:db8::1"},
		{name: "zone", body: "2606:4700:4700::1111%eth0"},
		{name: "CGNAT", body: "100.64.0.1"},
		{name: "multiple addresses", body: "8.8.8.8\n1.1.1.1"},
		{name: "HTML", body: "<html>8.8.8.8</html>"},
		{name: "empty", body: ""},
		{name: "too large", body: "8.8.8.8" + strings.Repeat(" ", relayPublicIPMaxBody)},
		{name: "error status", body: "8.8.8.8", status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", r.Method)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			got, err := queryRelayPublicIP(context.Background(), server.Client(), server.URL)
			if test.want == "" {
				if err == nil || got.IsValid() {
					t.Fatalf("query = %v, %v; want invalid address and error", got, err)
				}
			} else if err != nil || got.String() != test.want {
				t.Fatalf("query = %v, %v; want %s", got, err, test.want)
			}
			if requests.Load() != 1 {
				t.Fatalf("made %d lookup requests, want exactly one", requests.Load())
			}
		})
	}
}

func TestQueryRelayPublicIPRejectsRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		fmt.Fprint(w, "8.8.8.8")
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		t.Error("injected client's redirect callback must not be used")
		return nil
	}
	if got, err := queryRelayPublicIP(context.Background(), client, server.URL); err == nil || got.IsValid() {
		t.Fatalf("redirect query = %v, %v; want error", got, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("redirect was followed: %d requests", requests.Load())
	}
}

type relayIPRoundTripFunc func(*http.Request) (*http.Response, error)

func (f relayIPRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestQueryRelayPublicIPContextAndLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: relayIPRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > relayPublicIPTimeout {
			t.Error("lookup has no bounded total context deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	if got, err := queryRelayPublicIP(ctx, client, relayPublicIPEndpoint); !errors.Is(err, context.DeadlineExceeded) || got.IsValid() {
		t.Fatalf("canceled lookup = %v, %v; want deadline error", got, err)
	}
	for _, endpoint := range []string{"http://127.0.0.1", "https://user:pass@example.invalid", "not a URL"} {
		if got, err := queryRelayPublicIP(context.Background(), client, endpoint); err == nil || got.IsValid() {
			t.Errorf("endpoint %q = %v, %v; want error", endpoint, got, err)
		}
	}
	if got, err := queryRelayPublicIP(context.Background(), nil, relayPublicIPEndpoint); err == nil || got.IsValid() {
		t.Errorf("nil client = %v, %v; want error", got, err)
	}
	// A hostile stream cannot force the lookup to consume an unbounded body.
	body := &relayIPCountingBody{}
	client.Transport = relayIPRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	})
	if _, err := queryRelayPublicIP(context.Background(), client, relayPublicIPEndpoint); err == nil {
		t.Fatal("unbounded response was accepted")
	}
	if body.read != relayPublicIPMaxBody+1 || !body.closed {
		t.Fatalf("read %d bytes, closed=%v; want at most %d and closed", body.read, body.closed, relayPublicIPMaxBody+1)
	}
}

type relayIPCountingBody struct {
	read   int
	closed bool
}

func (b *relayIPCountingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}

func (b *relayIPCountingBody) Close() error { b.closed = true; return nil }

var _ io.ReadCloser = (*relayIPCountingBody)(nil)

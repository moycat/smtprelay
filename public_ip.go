package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	relayPublicIPEndpoint = "https://api64.ipify.org"
	relayPublicIPTimeout  = 5 * time.Second
	relayPublicIPMaxBody  = 128
)

// Exclude the IANA special-purpose registries, including globally reachable
// protocol/anycast services that are not ordinary relay host addresses.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var relaySpecialIPRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

var relayGlobalIPv6Range = netip.MustParsePrefix("2000::/3")

func isPublicRelayIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	// Native IPv6 global unicast currently comes from 2000::/3. This also
	// rejects translation, discard, reserved, and other non-host address space.
	if addr.Is6() && !relayGlobalIPv6Range.Contains(addr) {
		return false
	}
	for _, prefix := range relaySpecialIPRanges {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// Called once during startup; callers retain the result for all submissions.
func resolveRelayPublicIP(ctx context.Context, configured string) (netip.Addr, error) {
	configured = strings.TrimSpace(configured)
	if configured != "" && !strings.EqualFold(configured, "auto") {
		addr, err := netip.ParseAddr(configured)
		if err != nil || !isPublicRelayIP(addr) {
			return netip.Addr{}, fmt.Errorf("public_ip must be an ordinary public IPv4 or IPv6 address")
		}
		return addr.Unmap(), nil
	}
	client := newRelayPublicIPClient()
	defer client.CloseIdleConnections()
	return queryRelayPublicIP(ctx, client, relayPublicIPEndpoint)
}

func newRelayPublicIPClient() *http.Client {
	return &http.Client{
		Timeout: relayPublicIPTimeout,
		Transport: &http.Transport{
			// Environment proxies would report their exit address instead.
			Proxy:                 nil,
			TLSHandshakeTimeout:   relayPublicIPTimeout,
			ResponseHeaderTimeout: relayPublicIPTimeout,
		},
	}
}

func queryRelayPublicIP(ctx context.Context, client *http.Client, endpoint string) (netip.Addr, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return netip.Addr{}, fmt.Errorf("public IP lookup requires an HTTPS endpoint")
	}
	if client == nil {
		return netip.Addr{}, fmt.Errorf("public IP lookup requires an HTTP client")
	}
	ctx, cancel := context.WithTimeout(ctx, relayPublicIPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("create public IP lookup: %w", err)
	}
	// Copy the injected client so redirects are forbidden without mutating it.
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bounded.Do(request)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("public IP lookup: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("public IP lookup returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, relayPublicIPMaxBody+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read public IP lookup: %w", err)
	}
	if len(body) > relayPublicIPMaxBody {
		return netip.Addr{}, fmt.Errorf("public IP lookup response is too large")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !isPublicRelayIP(addr) {
		return netip.Addr{}, fmt.Errorf("public IP lookup returned a non-public or invalid address")
	}
	return addr.Unmap(), nil
}

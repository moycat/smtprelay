package main

import (
	"bytes"
	"fmt"
	"mime"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type relayHeader struct {
	name string
	raw  []byte
}

func (h relayHeader) value() string {
	_, value, _ := bytes.Cut(h.raw, []byte(":"))
	return strings.Join(strings.Fields(string(value)), " ")
}

// Split raw fields rather than reserializing a parsed MIMEHeader: untouched
// headers and the entire MIME body must retain their original bytes for DKIM.
func splitRelayHeaders(data []byte) ([]relayHeader, []byte, error) {
	var headers []relayHeader
	for offset := 0; offset < len(data); {
		n := bytes.IndexByte(data[offset:], '\n')
		if n < 0 {
			break
		}
		end := offset + n + 1
		line := bytes.TrimSuffix(data[offset:end-1], []byte("\r"))
		if len(line) == 0 {
			return headers, data[offset:], nil
		}
		for _, ch := range line {
			if ch < 32 && ch != '\t' || ch == 127 {
				return nil, nil, fmt.Errorf("invalid control character in message headers")
			}
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) == 0 {
				return nil, nil, fmt.Errorf("message starts with a folded header")
			}
			last := &headers[len(headers)-1]
			last.raw = data[offset-len(last.raw) : end]
		} else {
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				return nil, nil, fmt.Errorf("invalid message header field")
			}
			for _, ch := range line[:colon] {
				if ch < 33 || ch > 126 {
					return nil, nil, fmt.Errorf("invalid message header field name")
				}
			}
			headers = append(headers, relayHeader{strings.ToLower(string(line[:colon])), data[offset:end]})
		}
		offset = end
		if offset == len(data) {
			return headers, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("missing message header separator")
}

func sourceHeader(name string) bool {
	switch name {
	case "received", "x-received", "return-path", "received-spf", "x-received-spf",
		"authentication-results", "authentication-results-original", "x-authentication-results", "x-original-authentication-results",
		"arc-authentication-results", "arc-message-signature", "arc-seal",
		"forwarded", "x-real-ip", "x-sender-ip", "x-source-ip", "x-original-ip", "x-proxyuser-ip",
		"x-smtp-remote-ip", "x-ironport-remoteip":
		return true
	}
	for _, prefix := range []string{
		"x-originating-", "x-client-", "x-remote-", "x-forwarded-",
		"x-ms-exchange-organization-", "x-ms-exchange-forest-", "x-ms-exchange-crosstenant-",
		"x-forefront-", "x-spam-",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

var ipv4Literal = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

func containsIPAddress(value string) bool {
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err != nil {
		// An unreadable encoded word can conceal an address alongside otherwise
		// readable words. Treat ambiguous metadata as private.
		return true
	}
	value = decoded
	for _, candidate := range ipv4Literal.FindAllString(value, -1) {
		if _, err := netip.ParseAddr(candidate); err == nil {
			return true
		}
	}
	value = strings.ReplaceAll(strings.ToLower(value), "ipv6:", "")
	for _, candidate := range strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == ':' || r == '.')
	}) {
		// A diagnostic label may be adjacent to the literal (client:2001:db8::1).
		// IPv6 without a zone needs at most 45 bytes; bound suffix checks even
		// for arbitrarily long header values.
		if len(candidate) > 45 {
			candidate = candidate[len(candidate)-45:]
		}
		for start := 0; start < len(candidate); start++ {
			if start > 0 && candidate[start-1] != ':' {
				continue
			}
			if _, err := netip.ParseAddr(candidate[start:]); err == nil && strings.Contains(candidate[start:], ":") {
				return true
			}
			if strings.HasSuffix(candidate, ":") {
				if _, err := netip.ParseAddr(candidate[start : len(candidate)-1]); err == nil && strings.Contains(candidate[start:len(candidate)-1], ":") {
					return true
				}
			}
		}
	}
	return false
}

func privateDKIM(value string, changed map[string]bool) bool {
	if containsIPAddress(value) {
		return true
	}
	foundHeaders := false
	for _, tag := range strings.Split(value, ";") {
		name, content, ok := strings.Cut(tag, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "z": // Copied headers can retain encoded source information.
			return true
		case "h":
			foundHeaders = true
			for _, field := range strings.Split(content, ":") {
				if changed[strings.ToLower(strings.TrimSpace(field))] {
					return true
				}
			}
		}
	}
	return !foundHeaders
}

// prepareRelayMessage implements the submission privacy boundary shared by
// smarthost delivery and pipe commands. Connection metadata stays local.
func prepareRelayMessage(data []byte, serverName, id string, now time.Time, publicIP netip.Addr) ([]byte, error) {
	headers, body, err := splitRelayHeaders(data)
	if err != nil {
		return nil, err
	}
	if id == "" || strings.ContainsAny(id, "\r\n") || strings.ContainsAny(serverName, "\r\n") {
		return nil, fmt.Errorf("invalid relay trace identity")
	}
	domain := serverName
	if address, err := mail.ParseAddress("id@" + domain); err != nil || address.Address != "id@"+domain || containsIPAddress(domain) {
		domain = "smtprelay.invalid"
	}
	// Retain a numeric hop limit across the privacy boundary so a misrouted
	// message cannot loop forever after its previous trace headers are filtered.
	hops, traces, hopFields := 0, 0, 0
	for _, header := range headers {
		if header.name == "received" {
			traces++
		}
		if header.name == "x-smtprelay-hop-count" {
			hopFields++
			value := header.value()
			count, err := strconv.Atoi(value)
			if err != nil || strings.Trim(value, "0123456789") != "" || count < 1 || hopFields > 1 {
				return nil, fmt.Errorf("invalid relay hop count")
			}
			hops = count
		}
	}
	if traces > hops {
		hops = traces
	}
	if hops >= 50 {
		return nil, fmt.Errorf("too many relay hops")
	}
	changed := map[string]bool{"received": true, "x-smtprelay-hop-count": true}
	keep := make([]bool, len(headers))
	for i, header := range headers {
		keep[i] = true
		switch {
		case sourceHeader(header.name) || header.name == "x-smtprelay-hop-count":
			keep[i] = false
		case header.name == "message-id" || header.name == "resent-message-id":
			if containsIPAddress(header.value()) {
				headers[i].raw = fmt.Appendf(nil, "%s: <%s@%s>\r\n", string(header.raw[:bytes.IndexByte(header.raw, ':')]), id, domain)
				changed[header.name] = true
			}
		case header.name == "references" || header.name == "in-reply-to":
			keep[i] = !containsIPAddress(header.value())
		case strings.HasPrefix(header.name, "x-"):
			keep[i] = !containsIPAddress(header.value())
		}
		if !keep[i] {
			changed[header.name] = true
		}
	}
	// A signature can cover another DKIM-Signature, so propagate invalidation.
	for again := true; again; {
		again = false
		for i, header := range headers {
			if keep[i] && header.name == "dkim-signature" && privateDKIM(header.value(), changed) {
				keep[i], changed[header.name], again = false, true, true
			}
		}
	}
	serverAddress := ""
	if publicIP = publicIP.Unmap(); isPublicRelayIP(publicIP) {
		literal := publicIP.String()
		if publicIP.Is6() {
			literal = "IPv6:" + literal
		}
		serverAddress = " ([" + literal + "])"
	}
	result := fmt.Appendf(make([]byte, 0, len(data)+128), "Received: by %s%s id %s; %s\r\n", serverName, serverAddress, id, now.UTC().Format(time.RFC1123Z))
	result = fmt.Appendf(result, "X-Smtprelay-Hop-Count: %d\r\n", hops+1)
	for i, header := range headers {
		if keep[i] {
			result = append(result, header.raw...)
		}
	}
	return append(result, body...), nil
}

package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/mail"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

var privacyTestTime = time.Date(2026, time.October, 16, 12, 34, 56, 987654321, time.FixedZone("PDT", -7*60*60))

// Check the entire new trace field, then return the original message's remaining
// bytes so preservation checks do not depend on the new field's line ending.
func privacyMessageAfterReceived(t *testing.T, data []byte, serverName, id string, hopCounts ...int) []byte {
	t.Helper()
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		t.Fatalf("missing Received field line ending: %q", data)
	}
	line := strings.TrimSuffix(string(data[:end]), "\r")
	prefix := "Received: by " + serverName + " id " + id + "; "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("unexpected relay trace field: %q", line)
	}
	date, err := mail.ParseDate(strings.TrimPrefix(line, prefix))
	if err != nil {
		t.Fatalf("invalid relay trace date: %v", err)
	}
	_, offset := date.Zone()
	if offset != 0 || !date.Equal(privacyTestTime.UTC().Truncate(time.Second)) {
		t.Fatalf("trace date = %v, want UTC %v", date, privacyTestTime.UTC().Truncate(time.Second))
	}
	hops := 1
	if len(hopCounts) != 0 {
		hops = hopCounts[0]
	}
	remaining := data[end+1:]
	end = bytes.IndexByte(remaining, '\n')
	if end < 0 {
		t.Fatalf("missing relay hop counter: %q", remaining)
	}
	line = strings.TrimSuffix(string(remaining[:end]), "\r")
	if want := "X-Smtprelay-Hop-Count: " + strconv.Itoa(hops); line != want {
		t.Fatalf("hop counter = %q, want %q", line, want)
	}
	return remaining[end+1:]
}

func privacyReadMessage(t *testing.T, data []byte) *mail.Message {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("transformed message is invalid: %v", err)
	}
	return message
}

func TestPrepareRelayMessagePreservesUnrelatedBytes(t *testing.T) {
	for _, ending := range []string{"\r\n", "\n"} {
		t.Run(map[string]string{"\r\n": "CRLF", "\n": "LF"}[ending], func(t *testing.T) {
			const signature = "dKiM-Signature: v=1; a=rsa-sha256; d=signer.example; s=mail;"
			headers := strings.Join([]string{
				"fRoM: Example Sender <sender@example.com>",
				"To:\trecipient@example.net",
				"sUbJeCt: =?UTF-8?Q?Synthetic_=E2=9C=93?=",
				"\tcontinued subject with 192.0.2.55 as message content",
				"Message-ID: <20261016.123456.0001@example.com>",
				"Resent-Message-ID: <resent-safe@example.com>",
				"References: <old@example.com>",
				"\t<another@example.net>",
				"In-Reply-To: <old@example.com>",
				"X-Custom-Trace:  two  spaces\tand a tab",
				"X-Custom-Trace: second value",
				signature,
				"\th=from:to:subject:message-id:references:in-reply-to; bh=AAAA; b=BBBB",
				"MIME-Version: 1.0",
				"Content-Type: multipart/mixed; boundary=synthetic",
			}, ending)
			// Header-like body text and a historical address are message content.
			body := "--synthetic" + ending + "Content-Type: text/plain" + ending + ending +
				"Body bytes stay intact.\t  " + ending + "Received: from [2001:db8::55]" + ending +
				"Subject: text in the body" + ending + ".dot line" + ending + "--synthetic--" + ending
			input := []byte(headers + ending + ending + body)
			original := bytes.Clone(input)
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, original) {
				t.Fatalf("unrelated message bytes changed:\ngot  %q\nwant %q", remaining, original)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("input buffer was modified")
			}
		})
	}
}

func TestPrepareRelayMessageRemovesOriginMetadata(t *testing.T) {
	for _, ending := range []string{"\r\n", "\n"} {
		t.Run(map[string]string{"\r\n": "CRLF", "\n": "LF"}[ending], func(t *testing.T) {
			fields := []string{
				"Return-Path: <original-bounce@example.org>",
				"Received: from laptop.invalid ([192.0.2.11])",
				"\tby old-relay.example; old trace continuation",
				"rEcEiVeD: from another.invalid ([2001:db8::12])",
				"X-Received: by old-relay.example with id old",
				"Received-SPF: pass client-ip=198.51.100.13",
				"Authentication-Results: mx.example; spf=pass smtp.remote-ip=192.0.2.14",
				"X-Authentication-Results: previous.example; dkim=pass",
				"ARC-Seal: i=1; a=rsa-sha256; d=old.example; b=AAAA",
				"ARC-Message-Signature: i=1; a=rsa-sha256; h=from; b=BBBB",
				"ARC-Authentication-Results: i=1; old.example; spf=pass",
				"X-Originating-IP: [198.51.100.15]",
				"x-sEnDeR-iP: 192.0.2.16",
				"X-Client-IP: 2001:db8::17",
				"X-Remote-IP: 198.51.100.18",
				"X-Forwarded-For: 192.0.2.19, 198.51.100.20",
				"Forwarded: for=\"[2001:db8::21]\"; by=old.example",
				"X-Real-IP: 192.0.2.22",
				"X-Source-IP: 192.0.2.24",
				"X-Original-IP: 192.0.2.25",
				"X-ProxyUser-IP: 192.0.2.26",
				"X-SMTP-Remote-IP: 192.0.2.27",
				"X-IronPort-RemoteIP: 192.0.2.28",
				"X-Originating-Hostname: private-workstation",
				"X-Client-Hostname: private-workstation",
				"X-Remote-Hostname: private-workstation",
				"X-Forwarded-Host: private-workstation",
				"X-MS-Exchange-Organization-OriginalClientIPAddress: 192.0.2.23",
				"x-ms-exchange-forest-ArrivalHubServer: internal.old.example",
				"X-MS-Exchange-Organization-ArbitraryMetadata: internal workstation name",
				"X-MS-Exchange-CrossTenant-OriginalArrivalTime: private timestamp",
				"X-Forefront-Antispam-Report: original source metadata",
				"X-Spam-Report: original source metadata",
				"X-Legacy-Audit: received from [203.0.113.29]",
				"X-Unusual-Trace: received from [IPv6:2001:db8::30]",
			}
			before := "From: sender@example.com" + ending + "Subject: privacy fixture" + ending
			after := "To: recipient@example.net" + ending + "X-Keep: value" + ending + ending + "exact body" + ending
			input := []byte(before + strings.Join(fields, ending) + ending + after)
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id", 3); !bytes.Equal(remaining, []byte(before+after)) {
				t.Fatalf("origin metadata was not removed cleanly:\ngot  %q\nwant %q", remaining, before+after)
			}
			message := privacyReadMessage(t, got)
			if len(message.Header["Received"]) != 1 {
				t.Fatalf("expected exactly the relay's trace field, got %q", message.Header["Received"])
			}
		})
	}
}

func TestPrepareRelayMessageRewritesOnlyAddressBearingIDs(t *testing.T) {
	ids := []string{
		"<old@192.0.2.71>",
		"<old@[198.51.100.72]>",
		"<192.0.2.73.client@workstation.example>",
		"<old@[IPv6:2001:db8::74]>",
		"<old@[2001:db8::75]>",
		"<old@[::ffff:192.0.2.76]>",
	}
	for _, field := range []string{"Message-ID", "Resent-Message-ID"} {
		for _, oldID := range ids {
			t.Run(field+"/"+oldID, func(t *testing.T) {
				input := []byte("From: sender@example.com\r\n" + field + ": " + oldID + "\r\nSubject: keep\r\n\r\nbody\r\n")
				got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
				if err != nil {
					t.Fatal(err)
				}
				privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id")
				message := privacyReadMessage(t, got)
				values := message.Header[textproto.CanonicalMIMEHeaderKey(field)]
				if len(values) != 1 {
					t.Fatalf("rewritten %s count = %d, want one", field, len(values))
				}
				value := values[0]
				if value == oldID || !strings.HasPrefix(value, "<") || !strings.HasSuffix(value, "@relay.example>") || len(value) <= len("<@relay.example>") {
					t.Fatalf("invalid replacement %s: %q", field, value)
				}
				if bytes.Contains(got, []byte(oldID)) {
					t.Fatalf("historical address-bearing ID survived: %q", got)
				}
				body, err := io.ReadAll(message.Body)
				if err != nil || !bytes.Equal(body, []byte("body\r\n")) || message.Header.Get("Subject") != "keep" {
					t.Fatalf("unrelated content changed: body=%q, error=%v", body, err)
				}
			})
		}
	}
}

func TestPrepareRelayMessageReplacementIDDomainFallback(t *testing.T) {
	for _, serverName := range []string{"192.0.2.91", "[2001:db8::92]", "bad name"} {
		t.Run(serverName, func(t *testing.T) {
			got, err := prepareRelayMessage([]byte("Message-ID: <old@[198.51.100.93]>\r\n\r\nbody"), serverName, "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			value := privacyReadMessage(t, got).Header.Get("Message-ID")
			if !strings.HasPrefix(value, "<") || !strings.HasSuffix(value, "@smtprelay.invalid>") || len(value) <= len("<@smtprelay.invalid>") {
				t.Fatalf("replacement ID used an invalid domain: %q", value)
			}
		})
	}
}

func TestPrepareRelayMessageRemovesAddressBearingReferences(t *testing.T) {
	for _, field := range []string{"References", "In-Reply-To"} {
		for _, oldID := range []string{"<old@[198.51.100.101]>", "<old@[IPv6:2001:db8::102]>"} {
			t.Run(field+"/"+oldID, func(t *testing.T) {
				before := "From: sender@example.com\r\nReferences: <safe@example.net>\r\n"
				removed := field + ": <also-safe@example.com>\r\n\t" + oldID + "\r\n"
				after := "In-Reply-To: <safe@example.net>\r\nSubject: unchanged\r\n\r\nbody\n"
				got, err := prepareRelayMessage([]byte(before+removed+after), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
				if err != nil {
					t.Fatal(err)
				}
				if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, []byte(before+after)) {
					t.Fatalf("reference removal affected unrelated fields:\ngot  %q\nwant %q", remaining, before+after)
				}
			})
		}
	}
}

func TestPrepareRelayMessageRetainsOnlyUnaffectedDKIMSignatures(t *testing.T) {
	const safe = "dKiM-Signature: v=1; a=rsa-sha256; d=signer.example; s=mail;\r\n\th=from:subject:x-originating-ip-absent; bh=AAAA; b=BBBB\r\n"
	const oversignedAbsent = "DKIM-Signature: v=1; a=rsa-sha256; d=other.example; s=mail; h=from:x-remote-ip; bh=CCCC; b=DDDD\r\n"
	before := "From: sender@example.com\r\nSubject: keep exact\r\n"
	removedHeaders := "Received: from old.example [192.0.2.111]\r\nX-Client-IP: 198.51.100.112\r\n"
	removedSignatures := []string{
		"DKIM-Signature: v=1; d=signer.example; s=mail; h=from:received; b=AAAA\r\n",
		"DKIM-Signature: v=1; d=signer.example; s=mail;\r\n\th=from : X-CLIENT-IP : subject; b=AAAA\r\n",
		"DKIM-Signature: v=1; d=signer.example; s=mail; h=from; z=From:sender@example.com; b=AAAA\r\n",
		"DKIM-Signature: v=1; d=signer.example; s=mail; h=from; i=user@[192.0.2.113]; b=AAAA\r\n",
		"DKIM-Signature: v=1; d=signer.example; s=mail; h=from; i=user@[IPv6:2001:db8::114]; b=AAAA\r\n",
	}
	after := "To: recipient@example.net\r\n\r\nbody\r\n"
	input := []byte(before + safe + removedHeaders + strings.Join(removedSignatures, "") + oversignedAbsent + after)
	got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(before + safe + oversignedAbsent + after)
	if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id", 2); !bytes.Equal(remaining, want) {
		t.Fatalf("DKIM retention/removal did not match changed fields:\ngot  %q\nwant %q", remaining, want)
	}
}

func TestPrepareRelayMessageDropsDKIMSigningChangedIDs(t *testing.T) {
	for _, field := range []string{"Message-ID", "Resent-Message-ID", "References", "In-Reply-To"} {
		t.Run(field, func(t *testing.T) {
			keep := "DKIM-Signature: v=1; d=safe.example; s=mail; h=from:subject; b=AAAA\r\n"
			drop := "DKIM-Signature: v=1; d=old.example; s=mail; h=from:" + strings.ToUpper(field) + "; b=BBBB\r\n"
			input := []byte("From: sender@example.com\r\n" + keep + field + ": <old@[198.51.100.121]>\r\n" + drop + "Subject: keep\r\n\r\nbody")
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			message := privacyReadMessage(t, got)
			if len(message.Header["Dkim-Signature"]) != 1 || !bytes.Contains(got, []byte(keep)) || bytes.Contains(got, []byte(drop)) {
				t.Fatalf("signature over a changed %s survived or unrelated signature changed: %q", field, got)
			}
		})
	}
}

func TestPrepareRelayMessageDropsDependentDKIMSignatures(t *testing.T) {
	before := "From: sender@example.com\r\nSubject: unchanged\r\n"
	// Put the dependent signature first: invalidation must not depend on order.
	dependent := "DKIM-Signature: v=1; d=dependent.example; s=mail; h=from:dkim-signature; b=AAAA\r\n"
	copiedHeaders := "DKIM-Signature: v=1; d=original.example; s=mail; h=from; z=From:sender@example.com; b=BBBB\r\n"
	keep := "DKIM-Signature: v=1; d=unaffected.example; s=mail; h=from:subject; b=CCCC\r\n"
	after := "\r\nbody\r\n"
	got, err := prepareRelayMessage([]byte(before+dependent+copiedHeaders+keep+after), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, []byte(before+keep+after)) {
		t.Fatalf("dependent signature survived or unaffected bytes changed: %q", remaining)
	}
}

func TestPrepareRelayMessageDetectsEncodedAndLabelledAddresses(t *testing.T) {
	before := "From: sender@example.com\r\nSubject: unchanged\r\n"
	keep := "X-Normal-Encoded: =?UTF-8?Q?ordinary_=E2=9C=93_text?=\r\n\tstill folded\r\n"
	removed := []string{
		"X-Diagnostic: client:2001:db8::1",
		"X-Encoded-Q: =?UTF-8?Q?client_192=2E0=2E2=2E45?=",
		"X-Encoded-Base64: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("client 198.51.100.46")) + "?=",
		"X-Encoded-IPv6: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("client 2001:db8::47")) + "?=",
		"X-Encoded-Split: =?UTF-8?Q?192=2E0=2E?= =?UTF-8?Q?2=2E48?=",
		"X-Diagnostic: =?UTF-8?Q?64=2E181=2E231=2E105?= =?unsupported?Q?x?=",
	}
	after := "\r\nbody with 192.0.2.49 retained\r\n"
	got, err := prepareRelayMessage([]byte(before+keep+strings.Join(removed, "\r\n")+"\r\n"+after), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, []byte(before+keep+after)) {
		t.Fatalf("encoded source data survived or ordinary encoded bytes changed: %q", remaining)
	}
}

func TestPrepareRelayMessageRewritesIDDespiteUnrelatedEncodingFailure(t *testing.T) {
	const encodedID = "=?UTF-8?Q?64=2E181=2E231=2E105?= =?unsupported?Q?x?="
	input := []byte("From: sender@example.com\r\nMessage-ID: " + encodedID + "\r\nSubject: unchanged\r\n\r\nbody")
	got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id")
	message := privacyReadMessage(t, got)
	value := message.Header.Get("Message-ID")
	if !strings.HasPrefix(value, "<") || !strings.HasSuffix(value, "@relay.example>") || len(value) <= len("<@relay.example>") {
		t.Fatalf("encoded source ID was not rebuilt: %q", value)
	}
	if bytes.Contains(remaining, []byte(encodedID)) || message.Header.Get("Subject") != "unchanged" {
		t.Fatalf("encoded source ID survived or unrelated headers changed: %q", remaining)
	}
	body, err := io.ReadAll(message.Body)
	if err != nil || !bytes.Equal(body, []byte("body")) {
		t.Fatalf("body changed: %q, error=%v", body, err)
	}
}

func TestPrepareRelayMessageUsesOnlyServerPublicAddressInTrace(t *testing.T) {
	for _, address := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		t.Run(address, func(t *testing.T) {
			const remaining = "From: sender@example.com\r\nSubject: unchanged\r\n\r\nbody\r\n"
			input := []byte("Received: from client.example ([192.0.2.155]) by previous.example\r\nX-Originating-IP: [2001:db8::155]\r\n" + remaining)
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.MustParseAddr(address))
			if err != nil {
				t.Fatal(err)
			}
			literal := address
			if netip.MustParseAddr(address).Is6() {
				literal = "IPv6:" + address
			}
			want := "Received: by relay.example ([" + literal + "]) id opaque-relay-id; " + privacyTestTime.UTC().Format(time.RFC1123Z) + "\r\n" +
				"X-Smtprelay-Hop-Count: 2\r\n" + remaining
			if !bytes.Equal(got, []byte(want)) {
				t.Fatalf("public server trace differs or client metadata survived:\ngot  %q\nwant %q", got, want)
			}
		})
	}
}

func TestPrepareRelayMessageIgnoresNonPublicServerAddresses(t *testing.T) {
	for _, address := range []string{
		"10.1.2.3", "172.16.1.2", "192.168.1.2", "127.0.0.1", "169.254.1.2", "100.64.1.2", "0.0.0.0", "224.0.0.1",
		"::", "::1", "fd00::1", "fe80::1", "ff02::1", "::ffff:192.168.1.2",
	} {
		t.Run(address, func(t *testing.T) {
			input := []byte("From: sender@example.com\r\nSubject: unchanged\r\n\r\nbody")
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.MustParseAddr(address))
			if err != nil {
				t.Fatal(err)
			}
			if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, input) {
				t.Fatalf("non-public server address affected output: %q", remaining)
			}
		})
	}
}

func TestPrepareRelayMessageAcceptsCompleteHeaderOnlyMessages(t *testing.T) {
	for _, ending := range []string{"\r\n", "\n"} {
		t.Run(map[string]string{"\r\n": "CRLF", "\n": "LF"}[ending], func(t *testing.T) {
			input := []byte("From: sender@example.com" + ending + "Subject: header only" + ending + "\tfolded value" + ending)
			got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, input) {
				t.Fatalf("header-only message changed: got %q, want %q", remaining, input)
			}
		})
	}
}

func TestPrepareRelayMessagePreservesLoopProtection(t *testing.T) {
	tests := []struct {
		name, counter string
		traces, hops  int
	}{
		{name: "initial submission", hops: 1},
		{name: "one old trace", traces: 1, hops: 2},
		{name: "several old traces", traces: 3, hops: 4},
		{name: "counter dominates traces", counter: "5", traces: 2, hops: 6},
		{name: "traces dominate counter", counter: "1", traces: 3, hops: 4},
		{name: "last permitted counter", counter: "49", hops: 50},
		{name: "last permitted traces", traces: 49, hops: 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := "From: sender@example.com\r\n"
			var origin strings.Builder
			if tt.counter != "" {
				origin.WriteString("x-SMTPrelay-hop-count: " + tt.counter + "\r\n")
			}
			for i := 0; i < tt.traces; i++ {
				origin.WriteString("Received: from old.example by previous.example; old trace\r\n")
			}
			after := "Subject: retained\r\n\r\nbody\r\n"
			got, err := prepareRelayMessage([]byte(before+origin.String()+after), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id", tt.hops); !bytes.Equal(remaining, []byte(before+after)) {
				t.Fatalf("old hop metadata survived or unrelated bytes changed: %q", remaining)
			}
		})
	}
	// The newly inserted relay counter also changes a signature's signed input.
	input := []byte("From: sender@example.com\r\nDKIM-Signature: v=1; d=old.example; s=mail; h=from:x-smtprelay-hop-count; b=AAAA\r\n\r\nbody")
	got, err := prepareRelayMessage(input, "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if remaining := privacyMessageAfterReceived(t, got, "relay.example", "opaque-relay-id"); !bytes.Equal(remaining, []byte("From: sender@example.com\r\n\r\nbody")) {
		t.Fatalf("DKIM signing the new relay counter survived: %q", remaining)
	}
}

func TestPrepareRelayMessageRejectsInvalidOrExhaustedHopCount(t *testing.T) {
	tests := []struct {
		name, origin string
	}{
		{"zero", "X-Smtprelay-Hop-Count: 0\r\n"},
		{"negative", "X-Smtprelay-Hop-Count: -1\r\n"},
		{"plus sign", "X-Smtprelay-Hop-Count: +1\r\n"},
		{"empty", "X-Smtprelay-Hop-Count: \r\n"},
		{"text", "X-Smtprelay-Hop-Count: one\r\n"},
		{"fraction", "X-Smtprelay-Hop-Count: 1.5\r\n"},
		{"comment", "X-Smtprelay-Hop-Count: 1 (old)\r\n"},
		{"overflow", "X-Smtprelay-Hop-Count: 999999999999999999999999999999\r\n"},
		{"duplicate", "X-Smtprelay-Hop-Count: 1\r\nx-smtprelay-hop-count: 1\r\n"},
		{"limit counter", "X-Smtprelay-Hop-Count: 50\r\n"},
		{"over limit counter", "X-Smtprelay-Hop-Count: 51\r\n"},
		{"limit traces", strings.Repeat("Received: by old.example\r\n", 50)},
		{"over limit traces", strings.Repeat("Received: by old.example\r\n", 51)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareRelayMessage([]byte("From: sender@example.com\r\n"+tt.origin+"\r\nbody"), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err == nil || len(got) != 0 {
				t.Fatalf("invalid or exhausted relay counter did not fail closed: output=%q, error=%v", got, err)
			}
		})
	}
}

func TestPrepareRelayMessageRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{"missing colon", "From sender@example.com\r\n\r\nbody"},
		{"empty field name", ": value\r\n\r\nbody"},
		{"space in field name", "X Bad: value\r\n\r\nbody"},
		{"tab in field name", "X\tBad: value\r\n\r\nbody"},
		{"space before colon", "From : sender@example.com\r\n\r\nbody"},
		{"tab before colon", "From\t: sender@example.com\r\n\r\nbody"},
		{"control in field name", "X-\x01-Bad: value\r\n\r\nbody"},
		{"non ASCII field name", "X-名字: value\r\n\r\nbody"},
		{"orphan space continuation", " continuation\r\nFrom: sender@example.com\r\n\r\nbody"},
		{"orphan tab continuation", "\tcontinuation\nFrom: sender@example.com\n\nbody"},
		{"NUL in name", "X-\x00-Bad: value\r\n\r\nbody"},
		{"NUL in value", "From: sender\x00@example.com\r\n\r\nbody"},
		{"NUL in stripped header", "Received: from old\x00.example\r\n\r\nbody"},
		{"bare CR in value", "From: sender@example.com\rX-Injected: value\r\n\r\nbody"},
		{"bare CR in continuation", "Subject: value\n\tcontinued\rhidden\n\nbody"},
		{"incomplete final header", "From: sender@example.com\r\nSubject: value"},
		{"no line ending", "From: sender@example.com"},
		{"empty message", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareRelayMessage([]byte(tt.input), "relay.example", "opaque-relay-id", privacyTestTime, netip.Addr{})
			if err == nil || len(got) != 0 {
				t.Fatalf("malformed headers did not fail closed: output=%q, error=%v", got, err)
			}
		})
	}
}

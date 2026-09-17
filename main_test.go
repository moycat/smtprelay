package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/chrj/smtpd"
)

func setupSenderPolicy(t *testing.T) smtpd.Peer {
	t.Helper()
	oldSender, oldUsers, oldFilename := allowedSender, *allowedUsers, filename
	t.Cleanup(func() {
		allowedSender, *allowedUsers, filename = oldSender, oldUsers, oldFilename
	})
	allowedSender = nil
	*allowedUsers = filepath.Join(t.TempDir(), "users")
	// Passwords are not used: these tests start with an authenticated peer.
	if err := os.WriteFile(*allowedUsers, []byte("restricted unused joe@example.com,@trusted.example\nunrestricted unused\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AuthLoadFile(*allowedUsers); err != nil {
		t.Fatal(err)
	}
	return smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
}

func assertSMTPErrorCode(t *testing.T, err error, want int) {
	t.Helper()
	if want == 0 {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	var smtpErr smtpd.Error
	if !errors.As(err, &smtpErr) || smtpErr.Code != want {
		t.Fatalf("got error %v, want SMTP code %d", err, want)
	}
}

func TestHeaderSenderChecker(t *testing.T) {
	peer := setupSenderPolicy(t)
	tests := []struct {
		name     string
		username string
		pattern  string
		headers  string
		wantCode int
	}{
		{name: "allowed mailbox", username: "restricted", headers: "From: joe@example.com"},
		{name: "disallowed mailbox", username: "restricted", headers: "From: attacker@example.com", wantCode: 451},
		{name: "display name", username: "restricted", headers: "From: Joe Smith <joe@example.com>"},
		{name: "display name cannot authorize", username: "restricted", headers: "From: \"joe@example.com\" <attacker@example.com>", wantCode: 451},
		{name: "encoded display name", username: "restricted", headers: "From: =?UTF-8?Q?Joe_Smith?= <joe@example.com>"},
		{name: "case insensitive", username: "restricted", headers: "fRoM: JOE@EXAMPLE.COM"},
		{name: "allowed domain", username: "restricted", headers: "From: other@trusted.example"},
		{name: "domain suffix rejected", username: "restricted", headers: "From: other@trusted.example.evil", wantCode: 451},
		{name: "all mailboxes allowed", username: "restricted", headers: "From: joe@example.com, other@trusted.example"},
		{name: "second mailbox forbidden", username: "restricted", headers: "From: joe@example.com, attacker@example.com", wantCode: 451},
		{name: "first mailbox forbidden", username: "restricted", headers: "From: attacker@example.com, joe@example.com", wantCode: 451},
		{name: "folded addresses", username: "restricted", headers: "From: Joe <joe@example.com>,\r\n\tOther <other@trusted.example>"},
		{name: "folded forbidden address", username: "restricted", headers: "From: joe@example.com,\r\n attacker@example.com", wantCode: 451},
		{name: "duplicate From", username: "restricted", headers: "From: joe@example.com\r\nFrom: attacker@example.com", wantCode: 554},
		{name: "duplicate mixed case", username: "restricted", headers: "From: attacker@example.com\r\nfRoM: joe@example.com", wantCode: 554},
		{name: "duplicate allowed From", username: "restricted", headers: "From: joe@example.com\r\nFrom: joe@example.com", wantCode: 554},
		{name: "missing From", username: "restricted", headers: "Subject: test", wantCode: 554},
		{name: "Sender is not From", username: "restricted", headers: "Sender: joe@example.com", wantCode: 554},
		{name: "empty From", username: "restricted", headers: "From:", wantCode: 554},
		{name: "empty address list", username: "restricted", headers: "From: nobody:;", wantCode: 554},
		{name: "malformed address", username: "restricted", headers: "From: joe@example.com <", wantCode: 554},
		{name: "malformed message", username: "restricted", headers: "Not a header\r\nFrom: joe@example.com", wantCode: 554},
		{name: "regex allows", pattern: `^joe@example\.com$`, headers: "From: Joe <joe@example.com>"},
		{name: "regex rejects", pattern: `^joe@example\.com$`, headers: "From: attacker@example.com", wantCode: 451},
		{name: "regex checks mailbox only", pattern: `joe@example\.com`, headers: "From: \"joe@example.com\" <attacker@example.com>", wantCode: 451},
		{name: "regex requires From", pattern: `.*`, headers: "Subject: test", wantCode: 554},
		{name: "both policies allow", username: "restricted", pattern: `@example\.com$`, headers: "From: joe@example.com"},
		{name: "user rejects despite regex", username: "restricted", pattern: `@example\.com$`, headers: "From: attacker@example.com", wantCode: 451},
		{name: "regex rejects despite user", username: "restricted", pattern: `@example\.com$`, headers: "From: other@trusted.example", wantCode: 451},
		{name: "unrestricted user", username: "unrestricted", headers: "From: attacker@example.com"},
		{name: "unrestricted user missing From unchanged", username: "unrestricted", headers: "Subject: test"},
		{name: "unrestricted user still subject to regex", username: "unrestricted", pattern: `^joe@example\.com$`, headers: "From: attacker@example.com", wantCode: 451},
		{name: "unknown auth user fails closed", username: "missing", headers: "From: joe@example.com", wantCode: 451},
		{name: "no restrictions unchanged", headers: "Subject: test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer.Username = tt.username
			allowedSender = nil
			if tt.pattern != "" {
				allowedSender = regexp.MustCompile(tt.pattern)
			}
			data := []byte(tt.headers + "\r\n\r\nFrom: joe@example.com\r\nBody\r\n")
			assertSMTPErrorCode(t, headerSenderChecker(peer, data), tt.wantCode)
		})
	}
}

func TestMailHandlerChecksHeaderBeforeDelivery(t *testing.T) {
	peer := setupSenderPolicy(t)
	peer.Username = "restricted"
	oldCommand, oldRemotes, oldStrict := *command, remotes, *strictSender
	t.Cleanup(func() {
		*command, remotes, *strictSender = oldCommand, oldRemotes, oldStrict
	})
	remotes, *strictSender = nil, false

	for _, tt := range []struct {
		name     string
		from     string
		wantCode int
	}{
		{name: "forged header rejected", from: "attacker@example.com", wantCode: 451},
		{name: "different allowed header delivered", from: "other@trusted.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			*command = filepath.Join(t.TempDir(), "deliver")
			if err := os.WriteFile(*command, []byte("#!/bin/sh\ncat > \"$0.message\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("From: " + tt.from + "\r\nSubject: test\r\n\r\nOriginal body\r\n")
			env := smtpd.Envelope{Sender: "joe@example.com", Recipients: []string{"recipient@example.net"}, Data: data}
			// This envelope passes the original MAIL FROM check in both cases.
			assertSMTPErrorCode(t, senderChecker(peer, env.Sender), 0)
			assertSMTPErrorCode(t, mailHandler(peer, env), tt.wantCode)
			delivered, err := os.ReadFile(*command + ".message")
			if tt.wantCode != 0 {
				if !os.IsNotExist(err) {
					t.Fatalf("rejected mail reached the delivery command: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if !bytes.HasSuffix(delivered, data) {
				t.Fatalf("original headers or body changed during delivery: %q", delivered)
			}
		})
	}
}

func TestAddrAllowedNoDomain(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	if addrAllowed("bob.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedSingle(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}

	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob@abc.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedDifferentCase(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	testAddrs := []string{
		"joe@ABC.com",
		"Joe@abc.com",
		"JOE@abc.com",
		"JOE@ABC.COM",
	}
	for _, addr := range testAddrs {
		if !addrAllowed(addr, allowedAddrs) {
			t.Errorf("Address %v not allowed, but should be", addr)
		}
	}
}

func TestAddrAllowedLocal(t *testing.T) {
	allowedAddrs := []string{"joe"}

	if !addrAllowed("joe", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedMulti(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com", "bob@def.com"}
	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("bob@def.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob@abc.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedSingleDomain(t *testing.T) {
	allowedAddrs := []string{"@abc.com"}
	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("joe@def.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedMixed(t *testing.T) {
	allowedAddrs := []string{"app", "app@example.com", "@appsrv.example.com"}
	if !addrAllowed("app", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("app@example.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("ceo@example.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("root@appsrv.example.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("dev@appsrv.example.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("appsrv@example.com", allowedAddrs) {
		t.FailNow()
	}
}

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd"
)

func TestACMENotificationUsesExistingRemotes(t *testing.T) {
	messages := make(chan smtpd.Envelope, 3)
	address := startTestSMTP(t, nil, false, func(_ smtpd.Peer, env smtpd.Envelope) error {
		messages <- env
		return nil
	})
	remote, err := ParseRemote("smtp://" + address + "/sender@example.com")
	if err != nil {
		t.Fatal(err)
	}
	old := remotes
	t.Cleanup(func() { remotes = old })
	remotes = []*Remote{{Scheme: "smtp", Addr: "127.0.0.1:0", Hostname: "localhost"}, remote, remote}
	opts := acmeOptions{Domains: []string{"smtp.example.com"}, NotifyFrom: "alerts@example.com", NotifyTo: []string{"admin@example.com"}}
	notifyACMEFailure(context.Background(), opts, time.Now().Add(24*time.Hour))
	select {
	case env := <-messages:
		if env.Sender != "sender@example.com" || len(env.Recipients) != 1 || env.Recipients[0] != "admin@example.com" {
			t.Fatalf("unexpected envelope: %+v", env)
		}
		message, err := mail.ReadMessage(bytes.NewReader(env.Data))
		if err != nil {
			t.Fatal(err)
		}
		from, err := message.Header.AddressList("From")
		if err != nil || from[0].Address != env.Sender {
			t.Fatal("header and envelope sender differ")
		}
		body, _ := io.ReadAll(message.Body)
		if !strings.Contains(string(body), "smtp.example.com") || !strings.Contains(string(body), "Next attempt:") {
			t.Fatalf("incomplete notification: %s", body)
		}
	default:
		t.Fatal("notification did not reach a working remote")
	}
	if len(messages) != 0 {
		t.Fatal("notification broadcast to additional remotes")
	}
	opts.NotifyTo = nil
	notifyACMEFailure(context.Background(), opts, time.Now())
	if len(messages) != 0 {
		t.Fatal("disabled notification sent mail")
	}
}

func TestSendMailContextTimesOut(t *testing.T) {
	for _, scheme := range []string{"smtp", "smtps"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn) // never send a greeting or TLS response
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			remote := &Remote{Scheme: scheme, Addr: listener.Addr().String(), Hostname: "localhost"}
			if err := SendMailContext(ctx, remote, "alerts@example.com", []string{"admin@example.com"}, nil); err == nil {
				t.Fatal("stalled SMTP server did not time out")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancellation left an open SMTP connection")
			}
		})
	}
}

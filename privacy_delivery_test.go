package main

import (
	"bytes"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chrj/smtpd"
)

func TestPrivateSubmissionDelivery(t *testing.T) {
	oldCommand, oldRemotes, oldStrict, oldHostname := *command, remotes, *strictSender, *hostName
	oldSender, oldUsers := allowedSender, *allowedUsers
	oldPublicIP, oldPublicIPStr := relayPublicIP, *publicIPStr
	t.Cleanup(func() {
		*command, remotes, *strictSender, *hostName = oldCommand, oldRemotes, oldStrict, oldHostname
		allowedSender, *allowedUsers = oldSender, oldUsers
		relayPublicIP, *publicIPStr = oldPublicIP, oldPublicIPStr
	})
	*hostName, *strictSender, *allowedUsers = "relay.example", false, ""
	if err := IniParser(strings.NewReader("public_ip = 1.1.1.1\n"), flagset.Set); err != nil {
		t.Fatal(err)
	}
	publicIP, err := resolveRelayPublicIP(t.Context(), *publicIPStr)
	if err != nil {
		t.Fatal(err)
	}
	relayPublicIP = publicIP
	allowedSender = regexp.MustCompile(`^sender@example\.com$`)
	t.Setenv("SMTPRELAY_PEER", "203.0.113.99")
	*command = filepath.Join(t.TempDir(), "deliver")
	script := `#!/bin/sh
cat > "$0.message"
printf '%s\n' "$SMTPRELAY_FROM" "$SMTPRELAY_TO" > "$0.envelope"
if [ "${SMTPRELAY_PEER+x}" = x ]; then
  printf 'present' > "$0.peer"
else
  printf 'absent' > "$0.peer"
fi
`
	if err := os.WriteFile(*command, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	type delivery struct {
		peer smtpd.Peer
		env  smtpd.Envelope
	}
	deliveries := make(chan delivery, 1)
	remoteAddress := startTestSMTP(t, nil, false, func(peer smtpd.Peer, env smtpd.Envelope) error {
		deliveries <- delivery{peer, env}
		return nil
	})
	remote, err := ParseRemote("smtp://" + remoteAddress)
	if err != nil {
		t.Fatal(err)
	}
	remotes = []*Remote{remote}
	address := startTestSMTP(t, nil, false, mailHandler)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(conn, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Hello("c4b232ae2637"); err != nil {
		t.Fatal(err)
	}
	if err := client.Mail("sender@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.Rcpt("recipient@example.net"); err != nil {
		t.Fatal(err)
	}
	w, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	message := "Received: from client ([64.181.231.105]) by old.example; yesterday\r\n" +
		"X-Originating-IP: [2001:db8::15]\r\n" +
		"From: Sender <sender@example.com>\r\nTo: recipient@example.net\r\n" +
		"Message-ID: <synthetic@[64.181.231.105]>\r\nSubject: private submission\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		"AAECAwQF\r\n"
	if _, err := io.WriteString(w, message); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var delivered delivery
	select {
	case delivered = <-deliveries:
	case <-time.After(5 * time.Second):
		t.Fatal("smarthost did not receive message")
	}
	if delivered.env.Sender != "sender@example.com" || strings.Join(delivered.env.Recipients, ",") != "recipient@example.net" || delivered.peer.HeloName != "relay.example" {
		t.Fatalf("unexpected outbound SMTP identity or envelope: %+v %+v", delivered.peer, delivered.env)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(delivered.env.Data))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Header["Received"]) != 1 || !strings.HasPrefix(parsed.Header.Get("Received"), "by relay.example ([1.1.1.1]) id ") {
		t.Fatalf("unexpected trace: %v", parsed.Header["Received"])
	}
	if parsed.Header.Get("Subject") != "private submission" || parsed.Header.Get("From") != "Sender <sender@example.com>" || !strings.HasSuffix(parsed.Header.Get("Message-ID"), "@relay.example>") {
		t.Fatalf("unexpected content headers: %v", parsed.Header)
	}
	if publicIP != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("configured server IP was not used: %v", publicIP)
	}
	headerBytes, _, _ := bytes.Cut(delivered.env.Data, []byte("\n\n"))
	for _, source := range []string{"64.181.231.105", "2001:db8::15", "127.0.0.1", "203.0.113.99", "c4b232ae2637"} {
		if bytes.Contains(headerBytes, []byte(source)) {
			t.Fatalf("source metadata %q reached smarthost: %s", source, headerBytes)
		}
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil || string(body) != "AAECAwQF\n" {
		t.Fatalf("MIME body changed: %q, %v", body, err)
	}
	commandData, err := os.ReadFile(*command + ".message")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(commandData, []byte("\r\n"), []byte("\n")), delivered.env.Data) {
		t.Fatal("pipe and smarthost received different messages")
	}
	envelope, err := os.ReadFile(*command + ".envelope")
	if err != nil || string(envelope) != "sender@example.com\n[recipient@example.net]\n" {
		t.Fatalf("unexpected command envelope: %q, %v", envelope, err)
	}
	peer, err := os.ReadFile(*command + ".peer")
	if err != nil || string(peer) != "absent" {
		t.Fatalf("unexpected command connection metadata: %q, %v", peer, err)
	}
}

func TestPrivateSubmissionRejectsBeforeDelivery(t *testing.T) {
	oldCommand, oldRemotes, oldStrict := *command, remotes, *strictSender
	oldSender, oldUsers := allowedSender, *allowedUsers
	t.Cleanup(func() {
		*command, remotes, *strictSender = oldCommand, oldRemotes, oldStrict
		allowedSender, *allowedUsers = oldSender, oldUsers
	})
	*strictSender, allowedSender, *allowedUsers = false, nil, ""
	// If validation is bypassed, both a pipe invocation and a connection attempt
	// would be observable. Neither output path should run for a rejected message.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote, err := ParseRemote("smtp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	remotes = []*Remote{remote}
	peer := smtpd.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::33"), Port: 12345}, HeloName: "private-client"}
	for _, data := range []string{
		"From: sender@example.com\r\nReceived : from [192.0.2.5]\r\n\r\nbody\r\n",
		"From: sender@example.com\r\nX-Smtprelay-Hop-Count: 50\r\n\r\nbody\r\n",
	} {
		*command = filepath.Join(t.TempDir(), "deliver")
		if err := os.WriteFile(*command, []byte("#!/bin/sh\ncat > \"$0.message\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		env := smtpd.Envelope{Sender: "sender@example.com", Recipients: []string{"recipient@example.net"}, Data: []byte(data)}
		assertSMTPErrorCode(t, mailHandler(peer, env), 554)
		if _, err := os.Stat(*command + ".message"); !os.IsNotExist(err) {
			t.Fatalf("rejected message invoked pipe command: %v", err)
		}
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("rejected message reached smarthost")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("unexpected listener error: %v", err)
	}
}

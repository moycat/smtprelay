package main

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Each failed certificate attempt sends one message through the first working
// configured remote. It never submits mail to the local SMTP listeners.
func notifyACMEFailure(ctx context.Context, opts acmeOptions, retryAt time.Time) {
	if len(opts.NotifyTo) == 0 {
		return
	}
	to := make([]string, len(opts.NotifyTo))
	for i, address := range opts.NotifyTo {
		to[i] = (&mail.Address{Address: address}).String()
	}
	for _, remote := range remotes {
		from := opts.NotifyFrom
		if remote.Sender != "" {
			from = remote.Sender
		}
		if err := validateMailbox(from); err != nil {
			log.Error().Msg("cannot send ACME notification: remote sender is not a valid mailbox")
			continue
		}
		message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: smtprelay ACME certificate renewal failed\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCertificate request or renewal failed for: %s\r\nNext attempt: %s\r\n\r\nCheck the smtprelay logs for the error details. The previous certificate remains in use while it is valid.\r\n",
			(&mail.Address{Address: from}).String(), strings.Join(to, ", "), time.Now().Format(time.RFC1123Z),
			generateUUID(), strings.TrimPrefix(opts.Domains[0], "*."), strings.Join(opts.Domains, ", "), retryAt.Format(time.RFC3339))
		// Keep arbitrary CA/DNS error responses in local logs, not in email.
		sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := SendMailContext(sendCtx, remote, from, opts.NotifyTo, []byte(message))
		cancel()
		if err == nil {
			log.Info().Msg("ACME failure notification sent")
			return
		}
		log.Error().Err(err).Str("host", remote.Hostname).Msg("ACME failure notification failed")
		if ctx.Err() != nil {
			return
		}
	}
}

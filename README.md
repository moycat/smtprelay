# smtprelay

[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/decke/smtprelay?label=openssf%20scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/decke/smtprelay)

Simple Golang based SMTP relay/proxy server that accepts mail via SMTP
and forwards it directly to another SMTP server.


## Why another SMTP server?

Outgoing mails are usually send via SMTP to an MTA (Mail Transfer Agent)
which is one of Postfix, Exim, Sendmail or OpenSMTPD on UNIX/Linux in most
cases. You really don't want to setup and maintain any of those full blown
kitchensinks yourself because they are complex, fragile and hard to
configure.

My use case is simple. I need to send automatically generated mails from
cron via msmtp/sSMTP/dma, mails from various services and network printers
via a remote SMTP server without giving away my mail credentials to each
device which produces mail.


## Main features

* Simple configuration with ini file .env file or environment variables
* Supports SMTPS/TLS (465), STARTTLS (587) and unencrypted SMTP (25)
* Checks for sender (SMTP MAIL FROM and message From header), receiver, client IP
* Authentication support with file (LOGIN, PLAIN)
* Enforce encryption for authentication
* Forwards all mail to a smarthost (any SMTP server)
* Small codebase
* IPv6 support
* Aliases support (dynamic reload when alias file changes)
* Automatic ACME certificates using Cloudflare DNS, with TLS hot reload and failure emails

Sender restrictions (`allowed_sender` and authenticated users' allowed addresses)
apply to both the SMTP envelope sender and every mailbox in the message's `From`
header. When a sender restriction applies, a missing, malformed, or duplicate
`From` header is rejected after DATA, before forwarding or running an external
command. Display names are not used for address matching. The envelope sender and
header addresses may differ as long as each is allowed.

## Automatic TLS certificates (ACME)

Enable ACME to obtain and renew the certificate used by all SMTPS and STARTTLS
listeners. This version supports **Cloudflare DNS-01** and defaults to Let's
Encrypt. No HTTP listener or inbound port 80/443 is needed for validation.

Example configuration (replace the example domains and addresses):

```ini
listen = tls://0.0.0.0:465 starttls://0.0.0.0:587
acme_enabled = true
acme_domains = smtp.example.com
acme_email = admin@example.com
acme_storage = /var/lib/smtprelay/acme
acme_cf_token_file = /etc/smtprelay/cloudflare-token

; Optional failure emails, delivered through the existing remotes
acme_notify_to = admin@example.com
acme_notify_from = alerts@example.com
remotes = starttls://user:password@smtp.example.net:587
```

Put the Cloudflare API token in a file and set `acme_cf_token_file` to its path.
The file should contain only the token; surrounding whitespace is trimmed.
Set its permissions to **0600**. Other permissions produce a warning log but do
not prevent use. The file is read again for each certificate request, so replacing
its contents updates the token for the next attempt. The token needs both
**Zone / Zone / Read** and **Zone / DNS / Edit**, limited to the DNS zones involved.
See the [lego Cloudflare documentation](https://go-acme.github.io/lego/dns/cloudflare/)
for DNS propagation settings.

`acme_domains` accepts space- or comma-separated DNS names, including wildcards;
the DNS records used for validation must be publicly resolvable. Only these
configured names are requested, never arbitrary names received in TLS handshakes.
Enabling ACME agrees to the configured CA's subscriber terms. The optional
`acme_directory` setting overrides the Let's Encrypt directory URL and must use
HTTPS. There is one storage directory, with no CA-specific partition or file lock;
use it with one running smtprelay instance.

The storage directory contains the account key and a single certificate/key
bundle. Keep it persistent across restarts and restrict access to it. The default
is `acme` relative to the working directory; newly created directories have mode
0700 and files have mode 0600. Certificate updates are saved atomically before
being activated. ACME overrides `local_cert` and `local_key`; disabling ACME
restores the existing file-based certificate configuration. `tls_profile` and
`local_forcetls` continue to apply.

The background worker uses ACME Renewal Information (ARI) when available,
otherwise it renews after two thirds of the certificate's lifetime (half for
certificates valid for ten days or less). A valid cached certificate is available
immediately at startup. With no valid cached certificate, SMTP listeners wait
for the first successful issuance. Renewed certificates are used by new TLS
handshakes without restarting listeners or interrupting existing connections.

Each failed issuance, renewal, validation, or certificate-save attempt sends a
failure email when `acme_notify_to` is configured, then waits **24 hours** before
trying again. The retry timer is **only in memory**: after restarting, a certificate
that has reached its renewal threshold is retried immediately. There is no
separate notification interval, escalating alert policy, or notification server.
An old certificate remains available while valid; expired certificates are not
served to new TLS handshakes.

Notifications try existing `remotes` in order and stop after the first successful
delivery. They bypass local SMTP listeners and local sender/recipient filters;
a remote's sender override is applied to both MAIL FROM and the message's From
header. Each remote has a 30-second notification timeout. If every remote fails,
the failure is logged; there is no separate notification retry queue. Messages
contain the affected domains and next attempt time; detailed CA/DNS errors remain
in the local logs. Leave `acme_notify_to` empty to disable emails. When enabled,
`acme_notify_from` and at least one `remote` are required.

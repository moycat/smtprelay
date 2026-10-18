package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chrj/smtpd"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"golang.org/x/term"
)

func connectionChecker(peer smtpd.Peer) error {
	// This can't panic because we only have TCP listeners
	peerIP := peer.Addr.(*net.TCPAddr).IP

	if len(allowedNets) == 0 {
		// Special case: empty string means allow everything
		return nil
	}

	for _, allowedNet := range allowedNets {
		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	log.Warn().
		Str("ip", peerIP.String()).
		Msg("Connection refused from address outside of allowed_nets")
	return smtpd.Error{Code: 421, Message: "Denied"}
}

func addrAllowed(addr string, allowedAddrs []string) bool {
	if allowedAddrs == nil {
		// If absent, all addresses are allowed
		return true
	}

	addr = strings.ToLower(addr)

	// Extract optional domain part
	domain := ""
	if idx := strings.LastIndex(addr, "@"); idx != -1 {
		domain = strings.ToLower(addr[idx+1:])
	}

	// Test each address from allowedUsers file
	for _, allowedAddr := range allowedAddrs {
		allowedAddr = strings.ToLower(allowedAddr)

		// Three cases for allowedAddr format:
		if idx := strings.Index(allowedAddr, "@"); idx == -1 {
			// 1. local address (no @) -- must match exactly
			if allowedAddr == addr {
				return true
			}
		} else {
			if idx != 0 {
				// 2. email address (user@domain.com) -- must match exactly
				if allowedAddr == addr {
					return true
				}
			} else {
				// 3. domain (@domain.com) -- must match addr domain
				allowedDomain := allowedAddr[idx+1:]
				if allowedDomain == domain {
					return true
				}
			}
		}
	}

	return false
}

func senderChecker(peer smtpd.Peer, addr string) error {
	// check sender address from auth file if user is authenticated
	if localAuthRequired() && peer.Username != "" {
		user, err := AuthFetch(peer.Username)
		if err != nil {
			// Shouldn't happen: authChecker already validated username+password
			log.Warn().
				Str("peer", peer.Addr.String()).
				Str("username", peer.Username).
				Err(err).
				Msg("could not fetch auth user")
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}

		if !addrAllowed(addr, user.allowedAddresses) {
			log.Warn().
				Str("peer", peer.Addr.String()).
				Str("username", peer.Username).
				Str("sender_address", addr).
				Err(err).
				Msg("sender address not allowed for authenticated user")
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}
	}

	if allowedSender == nil {
		// Any sender is permitted
		return nil
	}

	if allowedSender.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.Warn().
		Str("sender_address", addr).
		Str("peer", peer.Addr.String()).
		Msg("sender address not allowed by allowed_sender pattern")
	return smtpd.Error{Code: 451, Message: "Bad sender address"}
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	if allowedRecipients == nil {
		// Any recipient is permitted
		return nil
	}

	if allowedRecipients.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.Warn().
		Str("peer", peer.Addr.String()).
		Str("recipient_address", addr).
		Msg("recipient address not allowed by allowed_recipients pattern")
	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}

func authChecker(peer smtpd.Peer, username string, password string) error {
	err := AuthCheckPassword(username, password)
	if err != nil {
		log.Warn().
			Str("peer", peer.Addr.String()).
			Str("username", username).
			Err(err).
			Msg("auth error")
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}
	return nil
}

func headerSenderChecker(peer smtpd.Peer, data []byte) error {
	if allowedSender == nil {
		if !localAuthRequired() || peer.Username == "" {
			return nil
		}
		user, err := AuthFetch(peer.Username)
		if err != nil {
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}
		if user.allowedAddresses == nil {
			return nil
		}
	}

	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return smtpd.Error{Code: 554, Message: "Invalid message headers"}
	}
	// Reject ambiguous duplicate headers instead of checking only the first one.
	if len(message.Header["From"]) != 1 {
		return smtpd.Error{Code: 554, Message: "Exactly one From header is required"}
	}
	addresses, err := message.Header.AddressList("From")
	if err != nil || len(addresses) == 0 {
		return smtpd.Error{Code: 554, Message: "Invalid From header"}
	}
	for _, address := range addresses {
		// Check the mailbox, not the display name, using the envelope policy.
		if err := senderChecker(peer, address.Address); err != nil {
			return err
		}
	}
	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	if err := headerSenderChecker(peer, env.Data); err != nil {
		return err
	}
	id := generateUUID()
	if id == "" {
		return smtpd.Error{Code: 421, Message: "Could not prepare message"}
	}
	data, err := prepareRelayMessage(env.Data, *hostName, id, time.Now(), relayPublicIP)
	if err != nil {
		return smtpd.Error{Code: 554, Message: "Invalid message headers"}
	}
	env.Data = data

	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	// Check for aliases
	aliasesMutex.RLock()
	for i, recipient := range env.Recipients {
		if alias, exists := aliasesList[recipient]; exists {
			env.Recipients[i] = alias
			log.Info().
				Str("original_recipient", recipient).
				Str("aliased_recipient", alias).
				Msg("Recipient address aliased")
		}
	}
	aliasesMutex.RUnlock()

	logger := log.With().
		Str("from", env.Sender).
		Strs("to", env.Recipients).
		Str("peer", peerIP).
		Str("uuid", id).
		Logger()

	var envRemotes []*Remote

	if *strictSender {
		for _, remote := range remotes {
			if remote.Sender == env.Sender {
				envRemotes = append(envRemotes, remote)
			}
		}
	} else {
		envRemotes = remotes
	}

	if len(envRemotes) == 0 && *command == "" {
		logger.Warn().Msg("no remote_host or command set; discarding mail")
		return smtpd.Error{Code: 554, Message: "There are no appropriate remote_host or command"}
	}

	if *command != "" {
		cmdLogger := logger.With().Str("command", *command).Logger()

		var stdout bytes.Buffer
		var stderr bytes.Buffer

		var environ []string
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			if name = strings.ToUpper(name); name != "SMTPRELAY_FROM" && name != "SMTPRELAY_TO" && name != "SMTPRELAY_PEER" {
				environ = append(environ, entry)
			}
		}
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_FROM", env.Sender))
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_TO", env.Recipients))

		cmd := exec.Cmd{
			Env:  environ,
			Path: *command,
		}

		cmd.Stdin = bytes.NewReader(env.Data)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			cmdLogger.Error().Err(err).Msg(stderr.String())
			return smtpd.Error{Code: 554, Message: "External command failed"}
		}

		cmdLogger.Info().Msg("pipe command successful: " + stdout.String())
	}

	for _, remote := range envRemotes {
		logger = logger.With().Str("host", remote.Addr).Logger()
		logger.Info().Msg("delivering mail from peer using smarthost")

		err := SendMail(
			remote,
			env.Sender,
			env.Recipients,
			env.Data,
		)
		if err != nil {
			var smtpError smtpd.Error

			switch err := err.(type) {
			case *textproto.Error:
				smtpError = smtpd.Error{Code: err.Code, Message: err.Msg}

				logger.Error().
					Int("err_code", err.Code).
					Str("err_msg", err.Msg).
					Msg("delivery failed")
			default:
				smtpError = smtpd.Error{Code: 421, Message: "Forwarding failed"}

				logger.Error().
					Err(err).
					Msg("delivery failed")
			}

			return smtpError
		}

		logger.Debug().Msg("delivery successful")
	}

	return nil
}

func generateUUID() string {
	uniqueID, err := uuid.NewRandom()

	if err != nil {
		log.Error().
			Err(err).
			Msg("could not generate UUIDv4")

		return ""
	}

	return uniqueID.String()
}

func getTLSConfig(manager *acmeManager) *tls.Config {
	conf := &tls.Config{}
	if manager != nil {
		// Leave Certificates empty so clients without SNI also use the current
		// certificate rather than a stale copy captured when the listener starts.
		conf.GetCertificate = manager.GetCertificate
	} else {
		cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
		if err != nil {
			log.Fatal().Err(err).Msg("cannot load X509 keypair")
		}
		conf.Certificates = []tls.Certificate{cert}
	}

	// TLS profile configuration
	// tls.Config.CipherSuites only affects TLS 1.0–1.2.

	profile := strings.ToLower(strings.TrimSpace(*tlsProfile))
	if profile == "" {
		profile = "default"
	}

	switch profile {
	case "default":
		// Go defaults (leave MinVersion/MaxVersion/CipherSuites unset).

	case "modern":
		// TLS 1.3+.
		conf.MinVersion = tls.VersionTLS13

	case "intermediate":
		// TLS 1.2+ with AEAD + ECDHE cipher suites only.
		// Mozilla "intermediate" — AEAD + ECDHE only.
		conf.MinVersion = tls.VersionTLS12
		conf.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}

	case "legacy":
		// Last resort: TLS 1.0+ and everything Go exposes for TLS 1.0–1.2.
		conf.MinVersion = tls.VersionTLS10

		allSuites := []uint16{}
		for _, cs := range tls.CipherSuites() {
			allSuites = append(allSuites, cs.ID)
		}
		for _, cs := range tls.InsecureCipherSuites() {
			allSuites = append(allSuites, cs.ID)
		}
		conf.CipherSuites = allSuites

	default:
		log.Warn().
			Str("tls_profile", profile).
			Msg("unknown tls_profile; using default")
	}

	return conf
}

func watchAliasFile() {
	if *aliasFile == "" {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to create file watcher for alias file")
		return
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					log.Info().
						Str("file", event.Name).
						Msg("alias file changed, reloading")

					err := LoadAliases(*aliasFile)
					if err != nil {
						log.Error().
							Str("file", *aliasFile).
							Err(err).
							Msg("failed to reload alias file")
					} else {
						log.Info().
							Int("count", len(aliasesList)).
							Msg("alias file reloaded successfully")
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().
					Err(err).
					Msg("file watcher error")
			}
		}
	}()

	err = watcher.Add(*aliasFile)
	if err != nil {
		log.Error().
			Str("file", *aliasFile).
			Err(err).
			Msg("failed to watch alias file")
	} else {
		log.Info().
			Str("file", *aliasFile).
			Msg("watching alias file for changes")
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bcrypt" {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: smtprelay bcrypt")
			os.Exit(1)
		}
		if err := runBcrypt(func() ([]byte, error) {
			return term.ReadPassword(int(os.Stdin.Fd()))
		}, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	ConfigLoad()
	defer closeLogger()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	defer stop()

	log.Debug().
		Str("version", appVersion).
		Msg("starting smtprelay")
	var publicIPErr error
	relayPublicIP, publicIPErr = resolveRelayPublicIP(ctx, *publicIPStr)
	if publicIPErr != nil {
		if value := strings.TrimSpace(*publicIPStr); value != "" && !strings.EqualFold(value, "auto") {
			log.Fatal().Err(publicIPErr).Msg("invalid public_ip configuration")
		}
		log.Warn().Err(publicIPErr).Msg("could not detect relay public IP; trace will identify the relay by hostname")
	}

	// Load allowed users file
	if localAuthRequired() {
		err := AuthLoadFile(*allowedUsers)
		if err != nil {
			log.Fatal().
				Str("file", *allowedUsers).
				Err(err).
				Msg("cannot load allowed users file")
		}
	}

	// Start watching alias file for changes
	watchAliasFile()

	var manager *acmeManager
	if *acmeEnabled {
		opts, err := loadACMEOptions()
		if err != nil {
			log.Fatal().Err(err).Msg("invalid ACME configuration")
		}
		hasTLS := false
		for _, listen := range listenAddrs {
			hasTLS = hasTLS || listen.protocol == "tls" || listen.protocol == "starttls"
		}
		if !hasTLS {
			log.Fatal().Msg("acme_enabled requires a TLS or STARTTLS listener")
		}
		manager, err = newACMEManager(opts, &legoIssuer{opts: opts})
		if err != nil {
			log.Fatal().Err(err).Msg("cannot initialize ACME storage")
		}
		manager.notify = func(ctx context.Context, retryAt time.Time) {
			notifyACMEFailure(ctx, opts, retryAt)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			manager.Run(ctx)
		}()
		defer func() { stop(); <-done }()
		log.Info().Msg("waiting for a valid ACME certificate before starting SMTP listeners")
		if err := manager.WaitReady(ctx); err != nil {
			return
		}
	}

	var servers []*smtpd.Server

	// Create a server for each desired listen address
	for _, listen := range listenAddrs {
		logger := log.With().Str("address", listen.address).Logger()

		server := &smtpd.Server{
			Hostname:          *hostName,
			WelcomeMessage:    *welcomeMsg,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			DataTimeout:       dataTimeout,
			MaxConnections:    *maxConnections,
			MaxMessageSize:    *maxMessageSize,
			MaxRecipients:     *maxRecipients,
			ConnectionChecker: connectionChecker,
			SenderChecker:     senderChecker,
			RecipientChecker:  recipientChecker,
			Handler:           mailHandler,
		}

		if localAuthRequired() {
			server.Authenticator = authChecker
		}

		var lsnr net.Listener
		var err error

		switch listen.protocol {
		case "":
			logger.Info().Msg("listening on address")
			lsnr, err = net.Listen("tcp", listen.address)

		case "starttls":
			server.TLSConfig = getTLSConfig(manager)
			server.ForceTLS = *localForceTLS

			logger.Info().Msg("listening on address (STARTTLS)")
			lsnr, err = net.Listen("tcp", listen.address)

		case "tls":
			server.TLSConfig = getTLSConfig(manager)

			logger.Info().Msg("listening on address (TLS)")
			lsnr, err = tls.Listen("tcp", listen.address, server.TLSConfig)

		default:
			logger.Fatal().
				Str("protocol", listen.protocol).
				Msg("unknown protocol in listen address")
		}

		if err != nil {
			logger.Fatal().
				Err(err).
				Msg("error starting listener")
		}
		servers = append(servers, server)

		go func() {
			server.Serve(lsnr)
		}()
	}

	<-ctx.Done()
	log.Info().Msg("shutting down in response to received signal")

	// First close the listeners
	for _, server := range servers {
		logger := log.With().Str("address", server.Address().String()).Logger()
		logger.Debug().Msg("Shutting down server")
		err := server.Shutdown(false)
		if err != nil {
			logger.Warn().
				Err(err).
				Msg("Shutdown failed")
		}
	}

	// Then wait for the clients to exit
	for _, server := range servers {
		logger := log.With().Str("address", server.Address().String()).Logger()
		logger.Debug().Msg("Waiting for server")
		err := server.Wait()
		if err != nil {
			logger.Warn().
				Err(err).
				Msg("Wait failed")
		}
	}

	log.Debug().Msg("done")

}

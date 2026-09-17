package main

import (
	"slices"
	"strings"
	"testing"
)

func TestACMEOptions(t *testing.T) {
	oldDomains, oldEmail, oldDir, oldStorage := *acmeDomains, *acmeEmail, *acmeDirectory, *acmeStorage
	oldTokenFile := *acmeCFTokenFile
	oldTo, oldFrom, oldRemotes := *acmeNotifyTo, *acmeNotifyFrom, remotes
	t.Cleanup(func() {
		*acmeDomains, *acmeEmail, *acmeDirectory, *acmeStorage = oldDomains, oldEmail, oldDir, oldStorage
		*acmeCFTokenFile = oldTokenFile
		*acmeNotifyTo, *acmeNotifyFrom, remotes = oldTo, oldFrom, oldRemotes
	})
	for _, tt := range []struct {
		name    string
		change  func()
		wantErr bool
	}{
		{name: "minimal"},
		{name: "INI token path", change: func() {
			if err := IniParser(strings.NewReader("acme_cf_token_file = /example/configured-token\n"), flagset.Set); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing token file", change: func() { *acmeCFTokenFile = "" }, wantErr: true},
		{name: "normalize domains", change: func() { *acmeDomains = "SMTP.EXAMPLE.COM., smtp.example.com *.example.com" }},
		{name: "missing domain", change: func() { *acmeDomains = "" }, wantErr: true},
		{name: "IP address", change: func() { *acmeDomains = "127.0.0.1" }, wantErr: true},
		{name: "invalid domain", change: func() { *acmeDomains = "foo/bar.example.com" }, wantErr: true},
		{name: "empty storage", change: func() { *acmeStorage = "" }, wantErr: true},
		{name: "insecure directory", change: func() { *acmeDirectory = "http://acme.example.com/directory" }, wantErr: true},
		{name: "invalid email", change: func() { *acmeEmail = "bad" }, wantErr: true},
		{name: "notifications", change: func() {
			*acmeNotifyTo = "admin@example.com, second@example.com"
			*acmeNotifyFrom = "alerts@example.com"
		}},
		{name: "notification without sender", change: func() { *acmeNotifyTo = "admin@example.com" }, wantErr: true},
		{name: "notification without remotes", change: func() { *acmeNotifyTo = "admin@example.com"; *acmeNotifyFrom = "alerts@example.com"; remotes = nil }, wantErr: true},
		{name: "header injection", change: func() { *acmeNotifyTo = "admin@example.com\r\nBcc: other@example.com" }, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			*acmeDomains, *acmeEmail, *acmeDirectory, *acmeStorage = "smtp.example.com", "", "https://acme.example.com/directory", "acme"
			*acmeCFTokenFile = "/example/cloudflare-token"
			*acmeNotifyTo, *acmeNotifyFrom, remotes = "", "", []*Remote{{}}
			if tt.change != nil {
				tt.change()
			}
			opts, err := loadACMEOptions()
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadACMEOptions() error = %v", err)
			}
			if tt.name == "INI token path" && opts.CFTokenFile != "/example/configured-token" {
				t.Fatalf("token path = %q", opts.CFTokenFile)
			}
			if tt.name == "normalize domains" && !slices.Equal(opts.Domains, []string{"smtp.example.com", "*.example.com"}) {
				t.Fatalf("domains = %v", opts.Domains)
			}
		})
	}
}

func TestSplitProto(t *testing.T) {
	var tests = []struct {
		input string
		proto string
		addr  string
	}{
		{
			input: "localhost",
			proto: "",
			addr:  "localhost",
		},
		{
			input: "tls://my.local.domain",
			proto: "tls",
			addr:  "my.local.domain",
		},
		{
			input: "starttls://my.local.domain",
			proto: "starttls",
			addr:  "my.local.domain",
		},
	}

	for i, test := range tests {
		testName := test.input
		t.Run(testName, func(t *testing.T) {
			pa := splitProto(test.input)
			if pa.protocol != test.proto {
				t.Errorf("Testcase %d: Incorrect proto: expected %v, got %v",
					i, test.proto, pa.protocol)
			}
			if pa.address != test.addr {
				t.Errorf("Testcase %d: Incorrect addr: expected %v, got %v",
					i, test.addr, pa.address)
			}
		})
	}
}

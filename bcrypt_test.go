package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBcryptCommandAuthentication(t *testing.T) {
	oldFilename := filename
	t.Cleanup(func() { filename = oldFilename })
	for _, password := range []string{"test-password", "  密码 with spaces  ", strings.Repeat("a", 72)} {
		var output, prompt bytes.Buffer
		input := []byte(password)
		if err := runBcrypt(func() ([]byte, error) { return input, nil }, &output, &prompt); err != nil {
			t.Fatal(err)
		}
		if prompt.String() != "Password: \n" {
			t.Fatalf("unexpected prompt: %q", prompt.String())
		}
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("password buffer was not cleared")
		}
		path := filepath.Join(t.TempDir(), "users")
		if err := os.WriteFile(path, []byte("testuser "+output.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if err := AuthLoadFile(path); err != nil {
			t.Fatal(err)
		}
		if err := AuthCheckPassword("testuser", password); err != nil {
			t.Fatalf("generated hash did not authenticate: %v", err)
		}
		if err := AuthCheckPassword("testuser", "wrong-password"); err == nil {
			t.Fatal("wrong password authenticated")
		}
	}
}

func TestBcryptCommandInvalidInput(t *testing.T) {
	for _, tt := range []struct {
		name, password string
		err            error
	}{
		{name: "empty"},
		{name: "too long", password: strings.Repeat("a", 73)},
		{name: "read error", err: errors.New("terminal unavailable")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output, prompt bytes.Buffer
			err := runBcrypt(func() ([]byte, error) { return []byte(tt.password), tt.err }, &output, &prompt)
			if err == nil || output.Len() != 0 {
				t.Fatalf("expected error and no hash, got error %v and output %q", err, output.String())
			}
		})
	}
}

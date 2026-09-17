package main

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

func runBcrypt(readPassword func() ([]byte, error), output, prompt io.Writer) error {
	if _, err := fmt.Fprint(prompt, "Password: "); err != nil {
		return err
	}
	password, err := readPassword()
	defer clear(password)
	fmt.Fprintln(prompt)
	if err != nil {
		return fmt.Errorf("read password from terminal: %w", err)
	}
	if len(password) == 0 {
		return errors.New("password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate bcrypt hash: %w", err)
	}
	_, err = fmt.Fprintln(output, string(hash))
	return err
}

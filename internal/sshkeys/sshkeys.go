package sshkeys

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	sshtoa "github.com/Mic92/ssh-to-age"
	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ReadPassphrase prompts the user for an SSH key passphrase.
// It is a package-level var so tests can replace it.
var ReadPassphrase = func(keyPath string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", keyPath)
	pass, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return pass, err
}

// ToAge converts an SSH private key to age identity strings,
// prompting for a passphrase if needed.
func ToAge(data []byte, keyPath string) (*string, *string, error) {
	priv, pub, err := sshtoa.SSHPrivateKeyToAge(data, nil)
	if err == nil {
		return priv, pub, nil
	}

	// Check if passphrase is needed
	var missingErr *ssh.PassphraseMissingError
	if !errors.As(err, &missingErr) {
		return nil, nil, err
	}

	passphrase, err := ReadPassphrase(keyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read passphrase")
	}

	return sshtoa.SSHPrivateKeyToAge(data, passphrase)
}

// FindEd25519Keys returns paths to all ed25519 private keys in ~/.ssh/
func FindEd25519Keys() []string {
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		data, err := os.ReadFile(path) // #nosec G304 G703 -- path is filepath.Join of a fixed dir and a ReadDir entry name
		if err != nil {
			continue
		}
		// Quick check for SSH private key marker
		if !bytes.Contains(data, []byte("OPENSSH PRIVATE KEY")) {
			continue
		}
		// Try to convert — ssh-to-age will reject non-ed25519
		if _, _, err := sshtoa.SSHPrivateKeyToAge(data, nil); err == nil {
			keys = append(keys, path)
			continue
		}
		// If passphrase-protected, include it — we'll confirm type at conversion time
		_, err = ssh.ParseRawPrivateKey(data)
		var missingErr *ssh.PassphraseMissingError
		if errors.As(err, &missingErr) {
			keys = append(keys, path)
		}
	}
	return keys
}

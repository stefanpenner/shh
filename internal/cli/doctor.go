package cli

import (
	"fmt"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/sshkeys"
)

// DoctorCheck represents the result of a single diagnostic check.
type DoctorCheck struct {
	Name    string
	Status  bool
	Message string
}

func RunDoctorChecks(getKeyFn func() (string, error), ghUsernameFn func() string, findSSHKeysFn func() []string, encFile string) []DoctorCheck {
	var checks []DoctorCheck
	var privKey string

	// 1. Age key
	key, err := getKeyFn()
	if err != nil {
		checks = append(checks, DoctorCheck{"age key", false, "no key found (run 'shh init')"})
	} else {
		privKey = key
		pubKey, _ := keyring.PublicKeyFrom(privKey)
		checks = append(checks, DoctorCheck{"age key", true, pubKey})
	}

	// 2. GitHub CLI
	username := ghUsernameFn()
	if username == "" {
		checks = append(checks, DoctorCheck{"github cli", false, "gh not installed or not logged in"})
	} else {
		checks = append(checks, DoctorCheck{"github cli", true, username})
	}

	// 3. SSH keys
	sshKeyPaths := findSSHKeysFn()
	if len(sshKeyPaths) == 0 {
		checks = append(checks, DoctorCheck{"ssh keys", false, "no ed25519 keys found in ~/.ssh"})
	} else {
		checks = append(checks, DoctorCheck{"ssh keys", true, fmt.Sprintf("%d ed25519 key(s) found", len(sshKeyPaths))})
	}

	// 4. Encrypted file
	ef, err := encfile.Load(encFile)
	if err != nil {
		checks = append(checks, DoctorCheck{"encrypted file", false, fmt.Sprintf("%s not found or invalid", encFile)})
	} else {
		checks = append(checks, DoctorCheck{"encrypted file", true, fmt.Sprintf("%s (%d secret(s), %d recipient(s))", encFile, len(ef.Secrets), len(ef.Recipients))})

		// 5. Recipient check (only if file exists and we have a key)
		if privKey != "" {
			pubKey, _ := keyring.PublicKeyFrom(privKey)
			found := false
			for _, pk := range ef.Recipients {
				if pk == pubKey {
					found = true
					break
				}
			}
			if found {
				checks = append(checks, DoctorCheck{"recipient", true, "your key is authorized"})
			} else {
				checks = append(checks, DoctorCheck{"recipient", false, "your key is NOT in the recipients list"})
			}
		}
	}

	return checks
}

func cmdDoctor() error {
	checks := RunDoctorChecks(keyring.GetKey, github.Username, sshkeys.FindEd25519Keys, envutil.FindEncFile())

	hasFailure := false
	for _, c := range checks {
		var icon string
		if c.Status {
			icon = successStyle.Render("✓")
		} else {
			icon = errorStyle.Render("✗")
			hasFailure = true
		}
		fmt.Printf("  %s %-16s %s\n", icon, c.Name, hintStyle.Render(c.Message))
	}

	if hasFailure {
		return errors.New("some checks failed")
	}
	return nil
}

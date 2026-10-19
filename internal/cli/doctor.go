package cli

import (
	"fmt"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/sshkeys"
)

type DoctorCheck struct {
	Name    string
	Status  bool
	Message string
}

func RunDoctorChecks(getKeyFn func() (string, error), ghUsernameFn func() string, findSSHKeysFn func() []string, encFile string) []DoctorCheck {
	var checks []DoctorCheck
	var privKey, pubKey string

	key, err := getKeyFn()
	if err != nil {
		checks = append(checks, DoctorCheck{"age key", false, "no key found (run 'shh init')"})
	} else {
		privKey = key
		pubKey, _ = crypto.PublicKeyFrom(privKey)
		checks = append(checks, DoctorCheck{"age key", true, pubKey})
	}

	username := ghUsernameFn()
	if username == "" {
		checks = append(checks, DoctorCheck{"github cli", false, "gh not installed or not logged in"})
	} else {
		checks = append(checks, DoctorCheck{"github cli", true, username})
	}

	sshKeyPaths := findSSHKeysFn()
	if len(sshKeyPaths) == 0 {
		checks = append(checks, DoctorCheck{"ssh keys", false, "no ed25519 keys found in ~/.ssh"})
	} else {
		checks = append(checks, DoctorCheck{"ssh keys", true, fmt.Sprintf("%d ed25519 key(s) found", len(sshKeyPaths))})
	}

	ef, err := encfile.Load(encFile)
	if err != nil {
		checks = append(checks, DoctorCheck{"encrypted file", false, fmt.Sprintf("%s not found or invalid", encFile)})
		return checks
	}
	checks = append(checks, DoctorCheck{"encrypted file", true, fmt.Sprintf("%s (%d secret(s), %d recipient(s))", encFile, len(ef.Secrets), len(ef.Recipients))})
	if privKey != "" {
		rc := recipientCheck(ef.Recipients, pubKey)
		checks = append(checks, rc)
		if rc.Status {
			checks = append(checks, macCheck(ef, privKey))
		}
	}
	if c, ok := extractableCheck(ef.Recipients); ok {
		checks = append(checks, c)
	}
	return checks
}

// macCheck decrypts with the caller's key, which verifies the file MAC first.
func macCheck(ef *encfile.EncryptedFile, privKey string) DoctorCheck {
	if _, err := encfile.DecryptSecrets(ef, privKey); err != nil {
		return DoctorCheck{"mac", false, "verification failed: " + err.Error()}
	}
	return DoctorCheck{"mac", true, "file MAC verified"}
}

// extractableCheck is advisory (Status stays true): extractable x25519 keys are
// a standing risk, not a broken install.
func extractableCheck(recipients map[string]string) (DoctorCheck, bool) {
	n := 0
	for _, pk := range recipients {
		if _, extractable := crypto.RecipientKind(pk); extractable {
			n++
		}
	}
	if n == 0 {
		return DoctorCheck{}, false
	}
	return DoctorCheck{"extractable keys", true, fmt.Sprintf("warning: %d extractable (x25519) recipient(s); on leak, rotate upstream secrets — git history stays readable", n)}, true
}

func recipientCheck(recipients map[string]string, pubKey string) DoctorCheck {
	for _, pk := range recipients {
		if pk == pubKey {
			return DoctorCheck{"recipient", true, "your key is authorized"}
		}
	}
	return DoctorCheck{"recipient", false, "your key is NOT in the recipients list"}
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

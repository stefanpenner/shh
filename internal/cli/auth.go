package cli

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/sshkeys"
)

func requireGHUsername() (string, error) {
	return github.RequireUsername()
}

// readSecret prompts on stderr and reads a line without echo. Overridable in
// tests. Kept off stdout so piped secrets stay clean.
var readSecret = func(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// readNewPassphrase prompts twice and confirms — a brain key is unrecoverable if
// you fat-finger it, so we never set one from a single unconfirmed entry.
func readNewPassphrase() (string, error) {
	p1, err := readSecret("New passphrase: ")
	if err != nil {
		return "", err
	}
	p2, err := readSecret("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passphrases do not match")
	}
	if strings.TrimSpace(p1) == "" {
		return "", errors.New("empty passphrase")
	}
	return p1, nil
}

// passphraseRecipient prompts for a new passphrase and returns the recipient
// (age1…) of the key it derives, for `users add --passphrase`.
func passphraseRecipient() (string, error) {
	fmt.Fprintln(os.Stderr, hintStyle.Render("Use a GENERATED high-entropy passphrase (e.g. 8 diceware words)."))
	fmt.Fprintln(os.Stderr, hintStyle.Render(".env.enc is committed, so a weak phrase can be brute-forced offline."))
	phrase, err := readNewPassphrase()
	if err != nil {
		return "", err
	}
	id, err := crypto.IdentityFromPassphrase(phrase)
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// runLoginPassphrase derives an age key from a passphrase and stores it in the
// keyring. The passphrase is never persisted or echoed — recovery re-derives it.
func runLoginPassphrase() error {
	phrase, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	}
	id, err := crypto.IdentityFromPassphrase(phrase)
	if err != nil {
		return err
	}
	return runLoginIdentity(id.String())
}

// runLoginIdentity stores a caller-supplied age identity in the OS keyring. The
// argument is either an identity string (AGE-SECRET-KEY-… or AGE-PLUGIN-…) or a
// path to an age identity file (as produced by `age-plugin-yubikey -i` /
// `age-plugin-se keygen`). This is how a non-extractable hardware key (YubiKey,
// Secure Enclave) is enrolled — its identity is a stub pointer, not a secret.
func runLoginIdentity(arg string) error {
	identity := strings.TrimSpace(arg)
	if data, err := os.ReadFile(arg); err == nil { // #nosec G304 -- user-supplied identity file
		identity = extractIdentity(string(data))
	}
	if err := crypto.ValidateIdentity(identity); err != nil {
		return errors.Wrap(err, "not a valid age identity")
	}
	if err := keyring.StoreKey(identity); err != nil {
		return errors.Wrap(err, "keyring store")
	}
	fmt.Println(successStyle.Render("Identity stored in OS keyring."))
	if pub, err := keyring.PublicKeyFrom(identity); err == nil {
		fmt.Printf("  key: %s\n", keyStyle.Render(pub))
	} else {
		fmt.Println(hintStyle.Render("Hardware/plugin key — add its recipient with: shh users add --name <name> --key age1…"))
	}
	return nil
}

// extractIdentity returns the first non-comment, non-blank line of an age
// identity file (the AGE-SECRET-KEY-… / AGE-PLUGIN-… line).
func extractIdentity(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return strings.TrimSpace(content)
}

func runInit(cmd *cobra.Command, args []string) error {
	if key, err := keyring.GetKey(); err == nil {
		pubKey, err := keyring.PublicKeyFrom(key)
		if err != nil {
			return err
		}
		fmt.Println("Already initialized. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	var privateKey, publicKey string

	// Try to find an ed25519 SSH key to derive from
	sshKeyPaths := sshkeys.FindEd25519Keys()
	if len(sshKeyPaths) > 0 {
		sshKey := sshKeyPaths[0]
		sshKeyData, err := os.ReadFile(sshKey) // #nosec G304
		if err != nil {
			return errors.Wrap(err, "read SSH key")
		}
		privKeyPtr, pubKeyPtr, err := sshkeys.ToAge(sshKeyData, sshKey)
		if err != nil {
			return errors.Wrap(err, "ssh-to-age")
		}
		privateKey = *privKeyPtr
		publicKey = *pubKeyPtr
		fmt.Printf("Using SSH key: %s\n", hintStyle.Render(sshKey))
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return errors.Wrap(err, "generate age key")
		}
		privateKey = identity.String()
		publicKey = identity.Recipient().String()
		fmt.Println(hintStyle.Render("No SSH ed25519 key found, generated a new age key."))
	}

	if err := keyring.StoreKey(privateKey); err != nil {
		return errors.Wrap(err, "keyring store")
	}

	fmt.Println(successStyle.Render("Key stored in OS keyring."))
	fmt.Println()
	fmt.Printf("  key: %s\n", keyStyle.Render(publicKey))
	fmt.Printf("   gh: %s\n", hintStyle.Render("https://github.com/"+username))
	fmt.Println()
	fmt.Printf("To add you to a project: shh users add %s\n", username)
	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	if key, err := keyring.GetKey(); err == nil {
		pubKey, _ := keyring.PublicKeyFrom(key)
		fmt.Println("Already logged in. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	// Load recipients from .env.enc if it exists
	var recipients map[string]string
	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		recipients = ef.Recipients
	}

	// Find local SSH keys and try to match against recipients
	for _, sshPath := range sshkeys.FindEd25519Keys() {
		data, _ := os.ReadFile(sshPath) // #nosec G304 -- path from FindEd25519Keys, restricted to ~/.ssh/
		privPtr, pubPtr, err := sshkeys.ToAge(data, sshPath)
		if err != nil {
			continue
		}
		for _, rk := range recipients { // ranging over nil map is safe (no iterations)
			if rk == *pubPtr {
				if err := keyring.StoreKey(*privPtr); err != nil {
					return errors.Wrap(err, "keyring store")
				}
				fmt.Printf("Matched SSH key %s\n", hintStyle.Render(sshPath))
				fmt.Println(successStyle.Render("Key stored in OS keyring."))
				fmt.Printf("  %s\n", keyStyle.Render(*pubPtr))
				return nil
			}
		}
	}

	if recipients != nil {
		return errors.Newf("your SSH key is not in the recipients list\n  ask a teammate to run: shh users add %s", username)
	}

	return errors.New("no .env.enc found — run 'shh init' to start a new project")
}

func cmdWhoami() error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return errors.New("not logged in (run 'shh init' or 'shh login')")
	}
	pubKey, err := keyring.PublicKeyFrom(privKey)
	if err != nil {
		// Plugin identity (YubiKey/Secure Enclave): the recipient isn't derivable
		// from the identity, and the SSH/X25519 matching below doesn't apply.
		fmt.Println(hintStyle.Render("  key: hardware/plugin identity (recipient not derivable)"))
		return nil
	}

	fmt.Printf("  key: %s\n", keyStyle.Render(pubKey))

	// Check if we're in a project's recipients list
	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				fmt.Printf(" user: %s\n", nameStyle.Render(name))
				break
			}
		}
	}

	// Check which SSH key this corresponds to
	for _, sshPath := range sshkeys.FindEd25519Keys() {
		data, err := os.ReadFile(sshPath) // #nosec G304 -- path from FindEd25519Keys, restricted to ~/.ssh/
		if err != nil {
			continue
		}
		_, pubPtr, err := sshkeys.ToAge(data, sshPath)
		if err != nil {
			continue
		}
		if *pubPtr == pubKey {
			fmt.Printf("  ssh: %s\n", hintStyle.Render(sshPath))
			break
		}
	}

	return nil
}

func cmdLogout() error {
	err := keyring.DeleteKey()
	if err != nil {
		return errors.New("no key found in keyring")
	}
	fmt.Println(successStyle.Render("Age key removed from OS keyring."))
	return nil
}

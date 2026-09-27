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
	"github.com/stefanpenner/shh/internal/qr"
	"github.com/stefanpenner/shh/internal/sshkeys"
)

// runLoginQRFile decodes a recovery QR image and enrolls the extractable age
// secret (Ring 0 paper path: shh login --qr-file recovery.png).
// Rejects URLs, plugins, and garbage — only AGE-SECRET-KEY-… (ParseExtractableSecret).
func runLoginQRFile(path string) error {
	payload, err := qr.DecodeFile(path)
	if err != nil {
		return errors.Wrap(err, "decode QR")
	}
	// DecodeFile already validated extractable secret; enroll without re-reading path as file.
	return runLoginIdentityString(payload)
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
// minPassphraseLen is a coarse weak-phrase floor at enrollment. .env.enc is
// committed and brute-forceable offline, so we reject obviously-weak inputs.
// (Login does not enforce it — an existing key must always remain unlockable.)
const minPassphraseLen = 12

func readNewPassphrase() (string, error) {
	p1, err := readSecret("New passphrase: ")
	if err != nil {
		return "", err
	}
	p2, err := readSecret("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	// Trim before compare/length so enrollment matches what IdentityFromPassphrase
	// derives (same Cf-aware trim).
	p1, p2 = crypto.TrimPassphrase(p1), crypto.TrimPassphrase(p2)
	if p1 != p2 {
		return "", errors.New("passphrases do not match")
	}
	if p1 == "" {
		return "", errors.New("empty passphrase")
	}
	if len(p1) < minPassphraseLen {
		return "", errors.Newf("passphrase too short (%d chars, need >= %d) — use a generated high-entropy passphrase (e.g. 8 diceware words)", len(p1), minPassphraseLen)
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
	return runLoginIdentityString(identity)
}

// runLoginIdentityString enrolls an already-resolved identity string (no file path probe).
// Used by QR login so a secret that happens to be a valid path name is not re-read as a file.
func runLoginIdentityString(identity string) error {
	identity = strings.TrimSpace(identity)
	if err := crypto.ValidateIdentity(identity); err != nil {
		return errors.Wrap(err, "not a valid age identity")
	}
	if err := keyring.StoreKey(identity); err != nil {
		return errors.Wrap(err, "keyring store")
	}
	fmt.Println(successStyle.Render("Identity stored in OS keyring."))
	if pub, err := crypto.PublicKeyFrom(identity); err == nil {
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

// enrolledRecipient is the public key already in the keyring.
// present is false when nothing is stored. err means no derivable
// recipient: init returns it, login still prints.
func enrolledRecipient() (string, bool, error) {
	key, err := keyring.GetKey()
	if err != nil {
		return "", false, nil
	}
	pub, err := crypto.PublicKeyFrom(key)
	return pub, true, err
}

func showStoredKey(lead, pub string) {
	fmt.Println(lead)
	fmt.Printf("  %s\n", keyStyle.Render(pub))
}

// readSSHAge reads an ed25519 private key and returns its age identity.
func readSSHAge(path string) (string, string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from FindEd25519Keys, restricted to ~/.ssh/
	if err != nil {
		return "", "", errors.Wrap(err, "read SSH key")
	}
	priv, pub, err := sshkeys.ToAge(data, path)
	if err != nil {
		return "", "", errors.Wrap(err, "ssh-to-age")
	}
	return *priv, *pub, nil
}

// sshMatch is the first local SSH key whose age recipient is listed.
func sshMatch(recipients map[string]string) (string, string, string, bool) {
	for _, path := range sshkeys.FindEd25519Keys() {
		priv, pub, err := readSSHAge(path)
		if err != nil {
			continue
		}
		for _, rk := range recipients {
			if rk == pub {
				return priv, pub, path, true
			}
		}
	}
	return "", "", "", false
}

// sshPathFor is the local SSH key that derives pub.
func sshPathFor(pubKey string) string {
	for _, path := range sshkeys.FindEd25519Keys() {
		_, pub, err := readSSHAge(path)
		if err != nil {
			continue
		}
		if pub == pubKey {
			return path
		}
	}
	return ""
}

func runInit(cmd *cobra.Command, args []string) error {
	pub, present, err := enrolledRecipient()
	if err != nil {
		return err
	}
	if present {
		showStoredKey("Already initialized. Your public key:", pub)
		return nil
	}

	username, err := github.RequireUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	var privateKey, publicKey string
	if paths := sshkeys.FindEd25519Keys(); len(paths) > 0 {
		privateKey, publicKey, err = readSSHAge(paths[0])
		if err != nil {
			return err
		}
		fmt.Printf("Using SSH key: %s\n", hintStyle.Render(paths[0]))
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
	pub, present, _ := enrolledRecipient()
	if present {
		showStoredKey("Already logged in. Your public key:", pub)
		return nil
	}

	username, err := github.RequireUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	var recipients map[string]string
	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		recipients = ef.Recipients
	}

	if priv, pub, path, ok := sshMatch(recipients); ok {
		if err := keyring.StoreKey(priv); err != nil {
			return errors.Wrap(err, "keyring store")
		}
		fmt.Printf("Matched SSH key %s\n", hintStyle.Render(path))
		fmt.Println(successStyle.Render("Key stored in OS keyring."))
		fmt.Printf("  %s\n", keyStyle.Render(pub))
		return nil
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
	pubKey, err := crypto.PublicKeyFrom(privKey)
	if err != nil {
		// Plugin identity (YubiKey/Secure Enclave): the recipient isn't derivable
		// from the identity, and the SSH/X25519 matching below doesn't apply.
		fmt.Println(hintStyle.Render("  key: hardware/plugin identity (recipient not derivable)"))
		return nil
	}

	fmt.Printf("  key: %s\n", keyStyle.Render(pubKey))

	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				fmt.Printf(" user: %s\n", nameStyle.Render(name))
				break
			}
		}
	}

	if path := sshPathFor(pubKey); path != "" {
		fmt.Printf("  ssh: %s\n", hintStyle.Render(path))
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

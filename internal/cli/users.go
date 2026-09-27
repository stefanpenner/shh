package cli

import (
	"fmt"
	"os"
	"strconv"

	"filippo.io/age"
	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/qr"
)

const shhUserPrefix = "shh-user://"

// recipientKindLabel renders the derived type of a recipient for `users list`.
// "extractable" is the security-relevant one: those keys are copyable, so the
// rotation-on-leak rule applies to them.
func recipientKindLabel(pubKey string) string {
	kind, extractable := crypto.RecipientKind(pubKey)
	switch {
	case extractable:
		return "extractable"
	case kind == "se":
		return "secure-enclave"
	default:
		return kind // yubikey, tpm, fido, …
	}
}

func usersListCmd() error {
	file := envutil.FindEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found (run 'shh set' first)", envutil.DefaultEncryptedFile)
	}

	var myKey string
	if priv, err := keyring.GetKey(); err == nil {
		myKey, _ = crypto.PublicKeyFrom(priv)
	}

	fmt.Println(headerStyle.Render("Authorized users"))
	i := 0
	for _, name := range envutil.SortedKeys(ef.Recipients) {
		i++
		pubKey := ef.Recipients[name]
		marker := ""
		if pubKey == myKey {
			marker = " " + youStyle.Render("(you)")
		}
		kind := hintStyle.Render("[" + recipientKindLabel(pubKey) + "]")
		fmt.Printf("  %d. %s  %s %s%s\n", i, keyStyle.Render(pubKey), nameStyle.Render(name), kind, marker)
	}
	return nil
}

func usersAddCmd(args []string, deployName, deployKey, qrOut string, printQR bool) error {
	newKey, name, generatedSecret, err := resolveAddRecipient(args, deployName, deployKey)
	if err != nil {
		return err
	}

	file := envutil.FindEncFile()
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	ef, err := loadOrCreateEnc(file, privKey)
	if err != nil {
		return err
	}

	for _, pk := range ef.Recipients {
		if pk == newKey {
			fmt.Println("User already present.")
			return nil
		}
	}
	if _, exists := ef.Recipients[name]; exists {
		return errors.Newf("name %q already in use (specify a different name)", name)
	}

	if err := rewrapAndSave(file, ef, name, newKey, privKey); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Added %s.", RecipientDisplayName(name))))
	return emitRecoveryQR(generatedSecret, qrOut, printQR)
}

// resolveAddRecipient returns the key and name to grant.
// generatedSecret is set only when this call minted an extractable identity.
func resolveAddRecipient(args []string, deployName, deployKey string) (string, string, string, error) {
	if deployName != "" {
		return deployRecipient(deployName, deployKey)
	}
	if len(args) > 0 {
		key, name, err := github.ResolveUserKey(args[0])
		return key, name, "", err
	}
	return "", "", "", errors.New("provide a GitHub username, age public key, or use --name for deploy keys")
}

func deployRecipient(deployName, deployKey string) (string, string, string, error) {
	if err := envutil.ValidateEnvName(deployName); err != nil {
		return "", "", "", errors.Wrapf(err, "invalid --name")
	}
	name := shhUserPrefix + deployName
	if deployKey != "" {
		// Encoding only (X25519 or a plugin recipient). No plugin binary or
		// hardware is required just to add someone.
		if err := crypto.ValidateRecipient(deployKey); err != nil {
			return "", "", "", errors.Newf("invalid age public key %q: %v", deployKey, err)
		}
		return deployKey, name, "", nil
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", "", errors.Wrap(err, "generate age key")
	}
	secret := identity.String()
	fmt.Println(hintStyle.Render("Secret key (store this in your CI/deploy platform as SHH_AGE_KEY):"))
	fmt.Println()
	fmt.Printf("  SHH_AGE_KEY=%s\n", secret)
	fmt.Println()
	fmt.Println(hintStyle.Render("This is the only time this key will be displayed."))
	fmt.Println(hintStyle.Render("Hint: " + qr.ChecksumHint(secret) + " — eyeball-check on paper cards."))
	return identity.Recipient().String(), name, secret, nil
}

// loadOrCreateEnc loads the vault. Any stat failure is treated as missing:
// seal openOrCreate's empty vault (current user is the first recipient).
func loadOrCreateEnc(file, privKey string) (*encfile.EncryptedFile, error) {
	if _, err := os.Stat(file); err == nil {
		return loadEncryptedFile(file)
	}

	secrets, recipients, err := openOrCreate(file, privKey)
	if err != nil {
		return nil, err
	}
	return encfile.EncryptSecrets(secrets, recipients)
}

func rewrapAndSave(file string, ef *encfile.EncryptedFile, name, newKey, privKey string) error {
	newRecipients := make(map[string]string, len(ef.Recipients)+1)
	for k, v := range ef.Recipients {
		newRecipients[k] = v
	}
	newRecipients[name] = newKey

	if err := encfile.ReWrapDataKey(ef, newRecipients, privKey); err != nil {
		return err
	}
	return encfile.Save(file, ef)
}

// emitRecoveryQR writes a PNG and/or terminal hint for a minted identity.
// The secret is never written to stdout as image bytes — file path only.
// --qr with no minted secret prints a note and writes nothing.
func emitRecoveryQR(secret, qrOut string, printQR bool) error {
	if secret == "" {
		if printQR || qrOut != "" {
			fmt.Println(hintStyle.Render("Note: --qr only applies when a new secret key is generated (omit --key)."))
		}
		return nil
	}
	if !printQR && qrOut == "" {
		return nil
	}

	if qrOut != "" {
		if err := qr.EncodeFile(secret, qrOut); err != nil {
			return errors.Wrap(err, "write QR PNG")
		}
		fmt.Println(successStyle.Render(fmt.Sprintf("QR written to %s (0600) — print or import to 1Password, then delete the file.", qrOut)))
	}
	if printQR {
		// Compact ANSI QR on stderr so stdout stays scriptable for SHH_AGE_KEY lines.
		code, err := qr.EncodeANSI(secret)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, hintStyle.Render("Recovery QR (scan into 1Password / paper; do not commit):"))
		fmt.Fprint(os.Stderr, code)
		fmt.Fprintln(os.Stderr)
	}
	return nil
}

func usersRemoveCmd(args []string) error {
	file := envutil.FindEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found", envutil.DefaultEncryptedFile)
	}

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	removedName, target, err := recipientToRemove(ef.Recipients, args[0])
	if err != nil {
		return err
	}
	newRecipients := withoutRecipient(ef.Recipients, removedName)
	if len(newRecipients) == 0 {
		return errors.New("cannot remove the last key")
	}

	secrets, err := encfile.DecryptSecrets(ef, privKey)
	if err != nil {
		return err
	}
	newEf, err := encfile.EncryptSecrets(secrets, newRecipients)
	if err != nil {
		return err
	}
	if err := encfile.Save(file, newEf); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Removed key: %s (%s)", removedName, target)))
	fmt.Println(hintStyle.Render("Data key rotated — all secrets re-encrypted."))
	return nil
}

func recipientToRemove(recipients map[string]string, target string) (name, shown string, err error) {
	names := envutil.SortedKeys(recipients)
	if n, convErr := strconv.Atoi(target); convErr == nil {
		if n < 1 || n > len(names) {
			return "", "", errors.Newf("invalid key number: %d", n)
		}
		target = recipients[names[n-1]]
	}

	var exact, display []string
	for recipientName, pk := range recipients {
		if pk == target || recipientName == target {
			exact = append(exact, recipientName)
		} else if RecipientDisplayName(recipientName) == target {
			display = append(display, recipientName)
		}
	}

	var candidates []string
	switch {
	case len(exact) > 0:
		candidates = exact
	case len(display) == 1:
		candidates = display
	case len(display) > 1:
		return "", "", errors.Newf("ambiguous match for %q: multiple recipients share that display name; use the full name (e.g. https://github.com/user) or public key instead", target)
	}
	if len(candidates) == 0 {
		return "", "", errors.Newf("key not found: %s", target)
	}
	return candidates[0], target, nil
}

func withoutRecipient(recipients map[string]string, removedName string) map[string]string {
	kept := make(map[string]string)
	for name, pk := range recipients {
		if name != removedName {
			kept[name] = pk
		}
	}
	return kept
}

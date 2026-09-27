package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
)

func cmdEncrypt(src string) error {
	if _, err := os.Stat(src); err != nil {
		return errors.Newf("file not found: %s", src)
	}

	plaintext, err := os.ReadFile(src) // #nosec G304 -- src is a CLI argument
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	secrets := encfile.ParsePlaintext(string(plaintext))
	if err := gateKeys(secrets, ""); err != nil {
		return err
	}

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	username, err := github.RequireUsername()
	if err != nil {
		return err
	}
	recipients, err := encfile.DefaultRecipients(privKey, username)
	if err != nil {
		return err
	}

	// If .env.enc already exists, preserve its recipients — but only after
	// authenticating it. Without this, a tampered .env.enc could redirect the new
	// secrets to an attacker's recipient (and previously reached age's plugin
	// exec with no MAC check at all).
	dest := src + ".enc"
	if existing, err := loadEncryptedFile(dest); err == nil {
		if _, derr := encfile.DecryptSecrets(existing, privKey); derr != nil {
			return errors.Wrap(derr, "refusing to reuse recipients from an unverifiable .env.enc")
		}
		recipients = existing.Recipients
	}

	if err := saveSecrets(dest, secrets, recipients); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Encrypted %s -> %s", src, dest)))
	fmt.Printf("You can now delete %s.\n", src)
	return nil
}

func cmdList(file string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(file, privKey)
	if err != nil {
		return err
	}
	for _, k := range envutil.SortedKeys(secrets) {
		fmt.Println(k)
	}
	return nil
}

func cmdEnv(file string, stdout bool, stderr io.Writer) error {
	if !stdout {
		return errors.New("refusing to write secrets to stdout; pass --stdout to confirm (e.g. eval $(shh env --stdout))")
	}
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(file, privKey)
	if err != nil {
		return err
	}
	for _, k := range envutil.SortedKeys(secrets) {
		if envutil.DangerousEnvVars[k] {
			fmt.Fprintf(stderr, "warning: skipping dangerous env var %q from secrets file\n", k)
			continue
		}
		fmt.Printf("export %s=%s\n", k, envutil.ShellQuote(secrets[k]))
	}
	return nil
}

func cmdEdit(file string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	secrets, recipients, err := openOrCreate(file, privKey)
	if err != nil {
		return err
	}

	tmpPath, stopSignals, err := writeEditTemp(file, secrets)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	defer stopSignals()

	changed, err := runEditor(tmpPath)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Println("No changes made.")
		return nil
	}

	edited, err := readEdited(tmpPath)
	if err != nil {
		return err
	}
	if err := gateKeys(edited, editReopenNote); err != nil {
		return err
	}
	return saveSecrets(file, edited, recipients)
}

func cmdSet(file, key, value string) error {
	if err := gateKey(key, ""); err != nil {
		return err
	}

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	secrets, recipients, err := openOrCreate(file, privKey)
	if err != nil {
		return err
	}

	_, existed := secrets[key]
	secrets[key] = value

	if err := saveSecrets(file, secrets, recipients); err != nil {
		return err
	}

	if existed {
		fmt.Println(successStyle.Render(fmt.Sprintf("Updated %s in %s.", key, file)))
	} else {
		fmt.Println(successStyle.Render(fmt.Sprintf("Added %s to %s.", key, file)))
	}
	return nil
}

func cmdRm(file, key string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	secrets, recipients, err := openExisting(file, privKey)
	if err != nil {
		return err
	}
	if _, exists := secrets[key]; !exists {
		return errors.Newf("key %q not found in %s", key, file)
	}
	delete(secrets, key)

	if err := saveSecrets(file, secrets, recipients); err != nil {
		return err
	}
	fmt.Println(successStyle.Render(fmt.Sprintf("Removed %s from %s.", key, file)))
	return nil
}

func cmdGet(file, key string, stderr io.Writer, checkTTY func() bool, quiet bool) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(file, privKey)
	if err != nil {
		return err
	}
	value, ok := secrets[key]
	if !ok {
		return errors.Newf("key %q not found in %s", key, file)
	}
	if !quiet && !checkTTY() {
		fmt.Fprintln(stderr, "warning: writing secret to stdout (not a terminal)")
	}
	fmt.Println(value)
	return nil
}

const editReopenNote = "; re-open with 'shh edit' to fix"

func gateKey(key, note string) error {
	if !envutil.EnvVarKeyPattern.MatchString(key) {
		return errors.Newf("invalid key name %q (must match [A-Za-z_][A-Za-z0-9_]*)%s", key, note)
	}
	if envutil.DangerousEnvVars[key] {
		return errors.Newf("setting %q is not allowed (dangerous environment variable)%s", key, note)
	}
	return nil
}

func gateKeys(secrets map[string]string, note string) error {
	for k := range secrets {
		if err := gateKey(k, note); err != nil {
			return err
		}
	}
	return nil
}

func openOrCreate(file, privKey string) (map[string]string, map[string]string, error) {
	if _, err := os.Stat(file); err == nil {
		return openExisting(file, privKey)
	}

	username, err := github.RequireUsername()
	if err != nil {
		return nil, nil, err
	}
	recipients, err := encfile.DefaultRecipients(privKey, username)
	if err != nil {
		return nil, nil, err
	}
	return make(map[string]string), recipients, nil
}

func openExisting(file, privKey string) (map[string]string, map[string]string, error) {
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return nil, nil, err
	}
	secrets, err := encfile.DecryptSecrets(ef, privKey)
	if err != nil {
		return nil, nil, err
	}
	return secrets, ef.Recipients, nil
}

func saveSecrets(file string, secrets, recipients map[string]string) error {
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	if err != nil {
		return err
	}
	return encfile.Save(file, ef)
}

// writeEditTemp writes plaintext beside the encrypted file, not on a shared
// temp dir. The interrupt handler is armed before the write; the caller
// defers stopSignals and Remove so it stays live through save.
func writeEditTemp(file string, secrets map[string]string) (string, func(), error) {
	editDir := filepath.Dir(file)
	if editDir == "" {
		editDir = "."
	}
	tmpFile, err := os.CreateTemp(editDir, ".shh-edit-*.env")
	if err != nil {
		return "", nil, errors.Wrap(err, "create temp file")
	}
	tmpPath := tmpFile.Name()

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()    // #nosec G104 -- best-effort cleanup; already returning Chmod error
		os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
		return "", nil, errors.Wrap(err, "chmod temp file")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(tmpPath) // #nosec G104 -- signal handler; best-effort cleanup
		os.Exit(1)
	}()
	stopSignals := func() { signal.Stop(sigCh) }

	if _, err := tmpFile.WriteString(encfile.FormatPlaintext(secrets)); err != nil {
		tmpFile.Close() // #nosec G104
		stopSignals()
		os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
		return "", nil, errors.Wrap(err, "write temp file")
	}
	if err := tmpFile.Close(); err != nil {
		stopSignals()
		os.Remove(tmpPath) // #nosec G104 -- best-effort cleanup
		return "", nil, errors.Wrap(err, "close temp file")
	}
	return tmpPath, stopSignals, nil
}

func runEditor(tmpPath string) (bool, error) {
	infoBefore, err := os.Stat(tmpPath)
	if err != nil {
		return false, err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpPath) // #nosec G702,G204
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	editorCmd.Env = envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY", "SHH_PLAINTEXT", "SHH_ALLOWED_AGE_PLUGINS")
	if err := editorCmd.Run(); err != nil {
		return false, errors.Wrap(err, "editor")
	}

	infoAfter, err := os.Stat(tmpPath)
	if err != nil {
		return false, err
	}
	return !infoAfter.ModTime().Equal(infoBefore.ModTime()), nil
}

func readEdited(tmpPath string) (map[string]string, error) {
	edited, err := os.ReadFile(tmpPath) // #nosec G304
	if err != nil {
		return nil, errors.Wrap(err, "read edited file")
	}
	return encfile.ParsePlaintext(string(edited)), nil
}

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
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

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	recipients, err := encfile.DefaultRecipients(privKey, username)
	if err != nil {
		return err
	}

	// If .env.enc already exists, preserve its recipients
	dest := src + ".enc"
	if existing, err := loadEncryptedFile(dest); err == nil {
		recipients = existing.Recipients
	}

	ef, err := encfile.EncryptSecrets(secrets, recipients)
	if err != nil {
		return err
	}

	if err := encfile.Save(dest, ef); err != nil {
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

func cmdEnv(file string, stderr io.Writer, checkTTY func() bool, quiet bool) error {
	if !quiet && !checkTTY() {
		fmt.Fprintln(stderr, "warning: writing secrets to stdout (not a terminal)")
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
		fmt.Printf("export %s=%s\n", k, envutil.ShellQuote(secrets[k]))
	}
	return nil
}

func cmdEdit(file string) error {
	var secrets map[string]string
	var recipients map[string]string

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	if _, err := os.Stat(file); err == nil {
		ef, err := loadEncryptedFile(file)
		if err != nil {
			return err
		}
		secrets, err = encfile.DecryptSecrets(ef, privKey)
		if err != nil {
			return err
		}
		recipients = ef.Recipients
	} else {
		secrets = make(map[string]string)
		username, err := requireGHUsername()
		if err != nil {
			return err
		}
		recipients, err = encfile.DefaultRecipients(privKey, username)
		if err != nil {
			return err
		}
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "shh-edit-*.env")
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close() // #nosec G104 -- best-effort cleanup; already returning Chmod error
		return errors.Wrap(err, "chmod temp file")
	}

	// Signal handler to clean up temp file
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(tmpPath) // #nosec G104 -- signal handler; best-effort cleanup
		os.Exit(1)
	}()
	defer signal.Stop(sigCh)

	if _, err := tmpFile.WriteString(encfile.FormatPlaintext(secrets)); err != nil {
		tmpFile.Close() // #nosec G104
		return errors.Wrap(err, "write temp file")
	}
	if err := tmpFile.Close(); err != nil {
		return errors.Wrap(err, "close temp file")
	}

	infoBefore, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpPath) // #nosec G702,G204
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	editorCmd.Env = envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY")
	if err := editorCmd.Run(); err != nil {
		return errors.Wrap(err, "editor")
	}

	infoAfter, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		fmt.Println("No changes made.")
		return nil
	}

	edited, err := os.ReadFile(tmpPath) // #nosec G304
	if err != nil {
		return errors.Wrap(err, "read edited file")
	}

	newSecrets := encfile.ParsePlaintext(string(edited))

	for k := range newSecrets {
		if !envutil.EnvVarKeyPattern.MatchString(k) {
			return errors.Newf("invalid key name %q (must match [A-Za-z_][A-Za-z0-9_]*); re-open with 'shh edit' to fix", k)
		}
		if envutil.DangerousEnvVars[k] {
			return errors.Newf("setting %q is not allowed (dangerous environment variable); re-open with 'shh edit' to fix", k)
		}
	}

	ef, err := encfile.EncryptSecrets(newSecrets, recipients)
	if err != nil {
		return err
	}
	return encfile.Save(file, ef)
}

func cmdSet(file, key, value string) error {
	if !envutil.EnvVarKeyPattern.MatchString(key) {
		return errors.Newf("invalid key name %q (must match [A-Za-z_][A-Za-z0-9_]*)", key)
	}
	if envutil.DangerousEnvVars[key] {
		return errors.Newf("setting %q is not allowed (dangerous environment variable)", key)
	}

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	var secrets map[string]string
	var recipients map[string]string

	if _, err := os.Stat(file); err == nil {
		ef, err := loadEncryptedFile(file)
		if err != nil {
			return err
		}
		secrets, err = encfile.DecryptSecrets(ef, privKey)
		if err != nil {
			return err
		}
		recipients = ef.Recipients
	} else {
		secrets = make(map[string]string)
		username, err := requireGHUsername()
		if err != nil {
			return err
		}
		recipients, err = encfile.DefaultRecipients(privKey, username)
		if err != nil {
			return err
		}
	}

	_, existed := secrets[key]
	secrets[key] = value

	ef, err := encfile.EncryptSecrets(secrets, recipients)
	if err != nil {
		return err
	}
	if err := encfile.Save(file, ef); err != nil {
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

	ef, err := loadEncryptedFile(file)
	if err != nil {
		return err
	}
	secrets, err := encfile.DecryptSecrets(ef, privKey)
	if err != nil {
		return err
	}

	if _, exists := secrets[key]; !exists {
		return errors.Newf("key %q not found in %s", key, file)
	}

	delete(secrets, key)

	newEf, err := encfile.EncryptSecrets(secrets, ef.Recipients)
	if err != nil {
		return err
	}
	if err := encfile.Save(file, newEf); err != nil {
		return err
	}
	fmt.Println(successStyle.Render(fmt.Sprintf("Removed %s from %s.", key, file)))
	return nil
}

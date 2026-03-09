package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
)

func usersListCmd() error {
	file := envutil.FindEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found (run 'shh set' first)", envutil.DefaultEncryptedFile)
	}

	var myKey string
	if priv, err := keyring.GetKey(); err == nil {
		myKey, _ = keyring.PublicKeyFrom(priv)
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
		fmt.Printf("  %d. %s  %s%s\n", i, keyStyle.Render(pubKey), nameStyle.Render(name), marker)
	}
	return nil
}

func usersAddCmd(args []string) error {
	newKey, name, err := github.ResolveUserKey(args[0])
	if err != nil {
		return err
	}
	file := envutil.FindEncFile()
	var ef *encfile.EncryptedFile

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	if _, err := os.Stat(file); err == nil {
		ef, err = loadEncryptedFile(file)
		if err != nil {
			return err
		}
	} else {
		// Create new empty file with current user
		username, err := requireGHUsername()
		if err != nil {
			return err
		}
		recipients, err := encfile.DefaultRecipients(privKey, username)
		if err != nil {
			return err
		}
		ef, err = encfile.EncryptSecrets(map[string]string{}, recipients)
		if err != nil {
			return err
		}
	}

	// Check for duplicate key
	for _, pk := range ef.Recipients {
		if pk == newKey {
			fmt.Println("User already present.")
			return nil
		}
	}

	// Check for name collision
	if _, exists := ef.Recipients[name]; exists {
		return errors.Newf("name %q already in use (specify a different name)", name)
	}

	// Add recipient and re-wrap data key
	newRecipients := make(map[string]string, len(ef.Recipients)+1)
	for k, v := range ef.Recipients {
		newRecipients[k] = v
	}
	newRecipients[name] = newKey

	if err := encfile.ReWrapDataKey(ef, newRecipients, privKey); err != nil {
		return err
	}

	if err := encfile.Save(file, ef); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Added %s.", RecipientDisplayName(name))))
	return nil
}

func usersRemoveCmd(args []string) error {
	target := args[0]

	file := envutil.FindEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found", envutil.DefaultEncryptedFile)
	}

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	// Resolve number to key
	names := envutil.SortedKeys(ef.Recipients)
	if n, err := strconv.Atoi(target); err == nil {
		if n < 1 || n > len(names) {
			return errors.Newf("invalid key number: %d", n)
		}
		target = ef.Recipients[names[n-1]]
	}

	// Find and remove the key
	var removedName string
	newRecipients := make(map[string]string)
	for name, pk := range ef.Recipients {
		if pk == target || name == target || RecipientDisplayName(name) == target {
			removedName = name
		} else {
			newRecipients[name] = pk
		}
	}

	if removedName == "" {
		return errors.Newf("key not found: %s", target)
	}
	if len(newRecipients) == 0 {
		return errors.New("cannot remove the last key")
	}

	// Decrypt all secrets, then re-encrypt with a fresh data key.
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

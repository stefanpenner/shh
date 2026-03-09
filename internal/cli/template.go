package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/merge"
	tmpl "github.com/stefanpenner/shh/internal/template"
)

func cmdTemplate(templatePath string, encFilePath string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(encFilePath, privKey)
	if err != nil {
		return err
	}

	var tmplBytes []byte
	if templatePath == "-" {
		tmplBytes, err = io.ReadAll(os.Stdin)
	} else {
		tmplBytes, err = os.ReadFile(templatePath) // #nosec G304 -- templatePath is a user-supplied CLI argument
	}
	if err != nil {
		return errors.Wrap(err, "read template")
	}

	result, err := tmpl.Render(string(tmplBytes), secrets)
	if err != nil {
		return err
	}

	fmt.Print(result)
	return nil
}

func cmdMerge(ancestorPath, oursPath, theirsPath string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}

	ancestor, err := loadEncryptedFile(ancestorPath)
	if err != nil {
		return errors.Wrap(err, "load ancestor")
	}
	ours, err := loadEncryptedFile(oursPath)
	if err != nil {
		return errors.Wrap(err, "load ours")
	}
	theirs, err := loadEncryptedFile(theirsPath)
	if err != nil {
		return errors.Wrap(err, "load theirs")
	}

	// Decrypt all three
	ancestorSecrets, err := encfile.DecryptSecrets(ancestor, privKey)
	if err != nil {
		return errors.Wrap(err, "decrypt ancestor")
	}
	oursSecrets, err := encfile.DecryptSecrets(ours, privKey)
	if err != nil {
		return errors.Wrap(err, "decrypt ours")
	}
	theirsSecrets, err := encfile.DecryptSecrets(theirs, privKey)
	if err != nil {
		return errors.Wrap(err, "decrypt theirs")
	}

	// 3-way merge secrets
	mergedSecrets, conflicts, mergeErr := merge.MergeSecrets(ancestorSecrets, oursSecrets, theirsSecrets)
	if mergeErr != nil {
		fmt.Fprintf(os.Stderr, "shh merge: conflict on keys: %s\n", strings.Join(conflicts, ", "))
		os.Exit(1)
	}

	// Merge recipients (union, with deletion support)
	mergedRecipients := merge.MergeStringMaps(ancestor.Recipients, ours.Recipients, theirs.Recipients)

	// Re-encrypt with merged values
	newEf, err := encfile.EncryptSecrets(mergedSecrets, mergedRecipients)
	if err != nil {
		return errors.Wrap(err, "re-encrypt merged secrets")
	}

	// Write result to the "ours" path (git convention)
	if err := encfile.Save(oursPath, newEf); err != nil {
		return errors.Wrap(err, "save merged file")
	}

	return nil
}

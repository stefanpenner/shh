package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/keyring"
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

	ancestor, ours, theirs, err := loadMergeSides(ancestorPath, oursPath, theirsPath)
	if err != nil {
		return err
	}

	merged, err := encfile.MergeFile(ancestor, ours, theirs, privKey,
		"shh merge: conflict on keys: %s", "re-encrypt merged secrets")
	if err != nil {
		return err
	}

	if err := encfile.Save(oursPath, merged); err != nil {
		return errors.Wrap(err, "save merged file")
	}
	return nil
}

func loadMergeSides(ancestorPath, oursPath, theirsPath string) (*encfile.EncryptedFile, *encfile.EncryptedFile, *encfile.EncryptedFile, error) {
	ancestor, err := loadSide(ancestorPath, "ancestor")
	if err != nil {
		return nil, nil, nil, err
	}
	ours, err := loadSide(oursPath, "ours")
	if err != nil {
		return nil, nil, nil, err
	}
	theirs, err := loadSide(theirsPath, "theirs")
	if err != nil {
		return nil, nil, nil, err
	}
	return ancestor, ours, theirs, nil
}

func loadSide(path, label string) (*encfile.EncryptedFile, error) {
	ef, err := loadEncryptedFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "load "+label)
	}
	return ef, nil
}

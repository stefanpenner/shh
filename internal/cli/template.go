package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

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

	merged, err := mergeSides(ancestor, ours, theirs, privKey)
	if err != nil {
		return err
	}

	if err := encfile.Save(oursPath, merged); err != nil {
		return errors.Wrap(err, "save merged file")
	}
	return nil
}

func loadMergeSides(ancestorPath, oursPath, theirsPath string) (*encfile.EncryptedFile, *encfile.EncryptedFile, *encfile.EncryptedFile, error) {
	ancestor, err := loadEncryptedFile(ancestorPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "load ancestor")
	}
	ours, err := loadEncryptedFile(oursPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "load ours")
	}
	theirs, err := loadEncryptedFile(theirsPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "load theirs")
	}
	return ancestor, ours, theirs, nil
}

func mergeSides(ancestor, ours, theirs *encfile.EncryptedFile, privKey string) (*encfile.EncryptedFile, error) {
	secrets, recipients, conflicts, err := encfile.MergeSides(ancestor, ours, theirs, privKey)
	if len(conflicts) > 0 {
		return nil, errors.Newf("shh merge: conflict on keys: %s", strings.Join(conflicts, ", "))
	}
	if err != nil {
		return nil, err
	}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt merged secrets")
	}
	return ef, nil
}

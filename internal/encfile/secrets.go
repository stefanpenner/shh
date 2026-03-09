package encfile

import (
	"crypto/hmac"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
)

func EncryptSecrets(secrets map[string]string, recipients map[string]string) (*EncryptedFile, error) {
	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		return nil, err
	}

	wrappedKeys, err := crypto.WrapDataKeyPerRecipient(dataKey, recipients)
	if err != nil {
		return nil, err
	}

	encSecrets := make(map[string]string, len(secrets))
	for k, v := range secrets {
		enc, err := crypto.EncryptValue(dataKey, k, v)
		if err != nil {
			return nil, errors.Wrapf(err, "encrypt %s", k)
		}
		encSecrets[k] = enc
	}

	mac := crypto.ComputeMAC(dataKey, crypto.FileVersion, wrappedKeys, recipients, encSecrets)

	return &EncryptedFile{
		Version:     crypto.FileVersion,
		MAC:         mac,
		Recipients:  recipients,
		WrappedKeys: wrappedKeys,
		Secrets:     encSecrets,
	}, nil
}

// DecryptSecrets decrypts the secrets in an EncryptedFile using the provided private key.
func DecryptSecrets(ef *EncryptedFile, privateKey string) (map[string]string, error) {
	pubKey, err := publicKeyFrom(privateKey)
	if err != nil {
		return nil, err
	}
	var myRecipientName string
	for name, pk := range ef.Recipients {
		if pk == pubKey {
			myRecipientName = name
			break
		}
	}
	if myRecipientName == "" {
		names := make([]string, 0, len(ef.Recipients))
		for name := range ef.Recipients {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, errors.Newf("your key (%s) is not in the recipients list\n  authorized: %s\n  ask a teammate to run: shh users add <your-github-username>",
			pubKey, strings.Join(names, ", "))
	}

	var dataKey []byte
	var expected string

	if ef.Version == 1 {
		// v1: single wrapped data key
		dataKey, err = crypto.UnwrapDataKey(ef.DataKey, privateKey)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt data key")
		}
		expected = crypto.ComputeMACv1(dataKey, ef.Version, ef.DataKey, ef.Recipients, ef.Secrets)
	} else {
		// v2: per-recipient wrapped keys
		wrappedKey, ok := ef.WrappedKeys[myRecipientName]
		if !ok {
			return nil, errors.Newf("no wrapped key found for recipient %s", myRecipientName)
		}
		dataKey, err = crypto.UnwrapDataKey(wrappedKey, privateKey)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt data key")
		}
		expected = crypto.ComputeMAC(dataKey, ef.Version, ef.WrappedKeys, ef.Recipients, ef.Secrets)
	}

	// Verify MAC
	if !hmac.Equal([]byte(expected), []byte(ef.MAC)) {
		return nil, errors.New("MAC verification failed — file may be tampered")
	}

	secrets := make(map[string]string, len(ef.Secrets))
	for k, v := range ef.Secrets {
		dec, err := crypto.DecryptValue(dataKey, k, v)
		if err != nil {
			return nil, errors.Wrapf(err, "decrypt %s", k)
		}
		secrets[k] = dec
	}

	return secrets, nil
}

// ReWrapDataKey re-wraps the data key for a new set of recipients using the provided private key.
func ReWrapDataKey(ef *EncryptedFile, newRecipients map[string]string, privateKey string) error {
	pubKey, err := publicKeyFrom(privateKey)
	if err != nil {
		return err
	}

	// Find our wrapped key (works for both v1 and v2)
	var dataKey []byte
	if ef.Version == 1 {
		dataKey, err = crypto.UnwrapDataKey(ef.DataKey, privateKey)
	} else {
		var myName string
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				myName = name
				break
			}
		}
		if myName == "" {
			return errors.New("your key is not in the recipients list")
		}
		wrappedKey, ok := ef.WrappedKeys[myName]
		if !ok {
			return errors.Newf("no wrapped key found for recipient %s", myName)
		}
		dataKey, err = crypto.UnwrapDataKey(wrappedKey, privateKey)
	}
	if err != nil {
		return errors.Wrap(err, "decrypt data key")
	}

	newWrappedKeys, err := crypto.WrapDataKeyPerRecipient(dataKey, newRecipients)
	if err != nil {
		return err
	}

	ef.DataKey = "" // clear v1 field
	ef.WrappedKeys = newWrappedKeys
	ef.Recipients = newRecipients
	ef.Version = crypto.FileVersion
	ef.MAC = crypto.ComputeMAC(dataKey, ef.Version, ef.WrappedKeys, ef.Recipients, ef.Secrets)
	return nil
}

// DefaultRecipients creates a default recipients map from the given private key and GitHub username.
func DefaultRecipients(privateKey string, ghUsername string) (map[string]string, error) {
	pubKey, err := publicKeyFrom(privateKey)
	if err != nil {
		return nil, err
	}
	return map[string]string{"https://github.com/" + ghUsername: pubKey}, nil
}

// publicKeyFrom derives the public key from an age private key string.
func publicKeyFrom(privateKey string) (string, error) {
	return crypto.PublicKeyFrom(privateKey)
}

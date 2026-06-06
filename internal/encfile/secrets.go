package encfile

import (
	"crypto/hmac"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
)

// verifyMAC checks the file MAC using the already-unwrapped dataKey.
// It handles both v1 and v2 file formats.
func verifyMAC(ef *EncryptedFile, dataKey []byte) error {
	var expected string
	if ef.Version == 1 {
		expected = crypto.ComputeMACv1(dataKey, ef.Version, ef.DataKey, ef.Recipients, ef.Secrets)
	} else {
		expected = crypto.ComputeMAC(dataKey, ef.Version, ef.WrappedKeys, ef.Recipients, ef.Secrets)
	}
	if !hmac.Equal([]byte(expected), []byte(ef.MAC)) {
		return errors.New("MAC verification failed — file may be tampered")
	}
	return nil
}

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

// resolveDataKey unwraps the file's data key with the given identity.
//
// Fast path: derive the identity's recipient and unwrap that recipient's entry
// directly (one unwrap → at most one hardware touch). Fallback: when the
// recipient can't be derived from the identity — which is the case for plugin
// identities (YubiKey, Secure Enclave), where age returns only a placeholder —
// try each wrapped key in turn. A plugin rejects stanzas that aren't for it
// without prompting, so only the matching entry triggers a touch.
func resolveDataKey(ef *EncryptedFile, privateKey string) ([]byte, error) {
	if ef.Version == 1 {
		dataKey, err := crypto.UnwrapDataKey(ef.DataKey, privateKey)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt data key")
		}
		return dataKey, nil
	}

	if pubKey, err := publicKeyFrom(privateKey); err == nil {
		// Recipient is derivable (X25519): look the entry up by name.
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				wrappedKey, ok := ef.WrappedKeys[name]
				if !ok {
					return nil, errors.Newf("no wrapped key found for recipient %s", name)
				}
				dataKey, err := crypto.UnwrapDataKey(wrappedKey, privateKey)
				if err != nil {
					return nil, errors.Wrap(err, "decrypt data key")
				}
				return dataKey, nil
			}
		}
		names := make([]string, 0, len(ef.Recipients))
		for name := range ef.Recipients {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, errors.Newf("your key (%s) is not in the recipients list\n  authorized: %s\n  ask a teammate to run: shh users add <your-github-username>",
			pubKey, strings.Join(names, ", "))
	}

	// Plugin identity: recipient not derivable — trial-unwrap each entry.
	wrappedNames := make([]string, 0, len(ef.WrappedKeys))
	for name := range ef.WrappedKeys {
		wrappedNames = append(wrappedNames, name)
	}
	sort.Strings(wrappedNames)
	for _, name := range wrappedNames {
		if dataKey, err := crypto.UnwrapDataKey(ef.WrappedKeys[name], privateKey); err == nil {
			return dataKey, nil
		}
	}
	return nil, errors.New("your key is not in the recipients list (no wrapped key could be unwrapped)")
}

// DecryptSecrets decrypts the secrets in an EncryptedFile using the provided private key.
func DecryptSecrets(ef *EncryptedFile, privateKey string) (map[string]string, error) {
	dataKey, err := resolveDataKey(ef, privateKey)
	if err != nil {
		return nil, err
	}

	// Verify MAC
	if err := verifyMAC(ef, dataKey); err != nil {
		return nil, err
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
	// Unwrap with the current identity — handles X25519 and plugin identities
	// (YubiKey/Secure Enclave) alike, so you can add/remove users while
	// authenticated with a hardware key.
	dataKey, err := resolveDataKey(ef, privateKey)
	if err != nil {
		return err
	}

	// Verify MAC before trusting and re-wrapping the data key.
	// Without this check, an attacker who can modify .env.enc could substitute
	// a crafted wrapped_key that decrypts to an attacker-controlled data key,
	// and users add/remove would silently re-wrap the attacker's key for all recipients.
	if err := verifyMAC(ef, dataKey); err != nil {
		return err
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

package keyring

import (
	"os"

	"github.com/cockroachdb/errors"
	gokeyring "github.com/zalando/go-keyring"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
)

const keychainService = "shh-age-key"

func GetKey() (string, error) {
	if key := os.Getenv("SHH_AGE_KEY"); key != "" {
		// Validate eagerly so callers get a clear error rather than a cryptic
		// failure deep in the encryption stack.
		if _, err := crypto.PublicKeyFrom(key); err != nil {
			return "", errors.New("SHH_AGE_KEY is not a valid age private key")
		}
		return key, nil
	}
	key, err := gokeyring.Get(keychainService, envutil.CurrentUsername())
	if err != nil {
		return "", errors.New("no key found (run 'shh init')")
	}
	return key, nil
}

func StoreKey(privateKey string) error {
	return gokeyring.Set(keychainService, envutil.CurrentUsername(), privateKey)
}

// PublicKeyFrom derives the public key from an age private key string.
// Delegates to crypto.PublicKeyFrom.
func PublicKeyFrom(privateKey string) (string, error) {
	return crypto.PublicKeyFrom(privateKey)
}

func DeleteKey() error {
	return gokeyring.Delete(keychainService, envutil.CurrentUsername())
}

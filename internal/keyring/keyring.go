package keyring

import (
	"os"

	"github.com/cockroachdb/errors"
	gokeyring "github.com/zalando/go-keyring"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
)

const keychainService = "shh-age-key"

// syncAccessGroup is the Mac App ID prefix plus ".shh".
// This team's prefix is 7E2J46XA8A. The Team ID T93925EZUT is not a valid group.
const syncAccessGroup = "7E2J46XA8A.shh"

var errNotFound = errors.New("keyring item not found")
var errSyncUnavailable = errors.New("icloud keychain unavailable")

type secretStore interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

type goKeyringStore struct{}

func (goKeyringStore) Get(service, account string) (string, error) {
	v, err := gokeyring.Get(service, account)
	if errors.Is(err, gokeyring.ErrNotFound) {
		return "", errNotFound
	}
	return v, err
}

func (goKeyringStore) Set(service, account, secret string) error {
	return gokeyring.Set(service, account, secret)
}

func (goKeyringStore) Delete(service, account string) error {
	err := gokeyring.Delete(service, account)
	if errors.Is(err, gokeyring.ErrNotFound) {
		return errNotFound
	}
	return err
}

type icloudStore struct{}

func (icloudStore) Get(service, account string) (string, error) {
	return syncGet(service, account)
}

func (icloudStore) Set(service, account, secret string) error {
	return syncSet(service, account, secret)
}

func (icloudStore) Delete(service, account string) error {
	return syncDelete(service, account)
}

var localStore secretStore = goKeyringStore{}
var syncStore secretStore = icloudStore{}

func syncStatus(st int32) error {
	switch st {
	case 0:
		return nil
	case -25300: // errSecItemNotFound
		return errNotFound
	case -34018: // errSecMissingEntitlement
		return errSyncUnavailable
	default:
		return errors.Newf("SecItem OSStatus %d", st)
	}
}

func GetKey() (string, error) {
	if key := os.Getenv("SHH_AGE_KEY"); key != "" {
		// Validate eagerly so callers get a clear error rather than a cryptic
		// failure deep in the encryption stack. Encoding-only — a plugin identity
		// (YubiKey/Secure Enclave) is valid here without touching the hardware.
		if err := crypto.ValidateIdentity(key); err != nil {
			return "", errors.New("SHH_AGE_KEY is not a valid age private key")
		}
		return key, nil
	}
	return getFor(envutil.CurrentUsername())
}

func getFor(account string) (string, error) {
	key, err := localStore.Get(keychainService, account)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, errNotFound) {
		return "", err
	}
	synced, serr := syncStore.Get(keychainService, account)
	if serr != nil {
		return "", errors.New("no key found (run 'shh init')")
	}
	if err := crypto.ValidateIdentity(synced); err != nil {
		return "", errors.New("icloud keychain identity is not a valid age private key")
	}
	if err := localStore.Set(keychainService, account, synced); err != nil {
		return "", errors.Wrap(err, "keyring store")
	}
	return synced, nil
}

func StoreKey(privateKey string) error {
	return storeFor(envutil.CurrentUsername(), privateKey)
}

func storeFor(account, privateKey string) error {
	if err := localStore.Set(keychainService, account, privateKey); err != nil {
		return err
	}
	if err := syncStore.Set(keychainService, account, privateKey); err != nil {
		if errors.Is(err, errSyncUnavailable) {
			return nil
		}
		return errors.Wrap(err, "icloud keychain")
	}
	return nil
}

func DeleteKey() error {
	return deleteFor(envutil.CurrentUsername())
}

func deleteFor(account string) error {
	localErr := localStore.Delete(keychainService, account)
	syncErr := syncStore.Delete(keychainService, account)
	localMissing := errors.Is(localErr, errNotFound)
	syncGone := syncErr == nil || errors.Is(syncErr, errNotFound) || errors.Is(syncErr, errSyncUnavailable)
	if localErr != nil && !localMissing {
		return localErr
	}
	if !syncGone {
		return errors.Wrap(syncErr, "icloud keychain")
	}
	if localMissing && syncErr != nil {
		return errNotFound
	}
	return nil
}

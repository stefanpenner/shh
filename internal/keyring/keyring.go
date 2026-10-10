package keyring

import (
	"os"

	"github.com/cockroachdb/errors"
	gokeyring "github.com/zalando/go-keyring"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
)

const keychainService = "shh-age-key"

// syncAccount is the one iCloud slot. It is not the unix user name.
const syncAccount = "shh"

// revokedMark is the cloud value after logout. It is not an age identity.
const revokedMark = "revoked"

// syncAccessGroup is the Mac App ID prefix plus ".shh".
// This team's prefix is YOUR_PREFIX. The Team ID YOUR_TEAM_ID is not a valid group.
const syncAccessGroup = "YOUR_PREFIX.shh"

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

func missingKey() error {
	return errors.New("no key found (run 'shh init')")
}

func getFor(account string) (string, error) {
	synced, serr := syncStore.Get(keychainService, syncAccount)
	if serr == nil {
		return takeCloud(account, synced)
	}
	if errors.Is(serr, errSyncUnavailable) {
		return localKey(account)
	}
	if !errors.Is(serr, errNotFound) {
		return "", serr
	}
	return adoptLocal(account)
}

func takeCloud(account, synced string) (string, error) {
	if synced == revokedMark {
		if err := clearLocal(account); err != nil {
			return "", err
		}
		return "", missingKey()
	}
	if err := crypto.ValidateIdentity(synced); err != nil {
		return "", errors.New("icloud keychain identity is not a valid age private key")
	}
	if err := localStore.Set(keychainService, account, synced); err != nil {
		return "", errors.Wrap(err, "keyring store")
	}
	return synced, nil
}

func adoptLocal(account string) (string, error) {
	key, err := localStore.Get(keychainService, account)
	if errors.Is(err, errNotFound) {
		return "", missingKey()
	}
	if err != nil {
		return "", err
	}
	if err := crypto.ValidateIdentity(key); err != nil {
		return "", errors.New("keyring identity is not a valid age private key")
	}
	if err := syncStore.Set(keychainService, syncAccount, key); err != nil {
		if errors.Is(err, errSyncUnavailable) {
			return key, nil
		}
		return "", errors.Wrap(err, "icloud keychain")
	}
	return key, nil
}

func localKey(account string) (string, error) {
	key, err := localStore.Get(keychainService, account)
	if errors.Is(err, errNotFound) {
		return "", missingKey()
	}
	return key, err
}

func clearLocal(account string) error {
	err := localStore.Delete(keychainService, account)
	if err == nil || errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

func StoreKey(privateKey string) error {
	return storeFor(envutil.CurrentUsername(), privateKey)
}

func storeFor(account, privateKey string) error {
	if err := syncStore.Set(keychainService, syncAccount, privateKey); err != nil {
		return errors.Wrap(err, "icloud keychain")
	}
	if err := localStore.Set(keychainService, account, privateKey); err != nil {
		return errors.Wrap(err, "keyring store")
	}
	return nil
}

func DeleteKey() error {
	return deleteFor(envutil.CurrentUsername())
}

func deleteFor(account string) error {
	synced, serr := syncStore.Get(keychainService, syncAccount)
	if serr != nil && !errors.Is(serr, errNotFound) {
		return errors.Wrap(serr, "icloud keychain")
	}
	_, lerr := localStore.Get(keychainService, account)
	if lerr != nil && !errors.Is(lerr, errNotFound) {
		return lerr
	}
	cloudEmpty := errors.Is(serr, errNotFound) || synced == revokedMark
	localEmpty := errors.Is(lerr, errNotFound)
	if cloudEmpty && localEmpty {
		return errNotFound
	}
	if err := syncStore.Set(keychainService, syncAccount, revokedMark); err != nil {
		return errors.Wrap(err, "icloud keychain")
	}
	return clearLocal(account)
}

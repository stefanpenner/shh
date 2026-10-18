//go:build !darwin || !cgo

package keyring

// Without cgo (the release builds: CGO_ENABLED=0, cross-compiled) there is no
// iCloud Keychain sync; the local keychain still works.

func syncGet(service, account string) (string, error) {
	return "", errSyncUnavailable
}

func syncSet(service, account, secret string) error {
	return errSyncUnavailable
}

func syncDelete(service, account string) error {
	return errSyncUnavailable
}

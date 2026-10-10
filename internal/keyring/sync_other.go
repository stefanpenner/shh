//go:build !darwin

package keyring

func syncGet(service, account string) (string, error) {
	return "", errSyncUnavailable
}

func syncSet(service, account, secret string) error {
	return errSyncUnavailable
}

func syncDelete(service, account string) error {
	return errSyncUnavailable
}

//go:build darwin && icloudlive

package keyring

import "testing"

// Signs nothing. An unsigned test binary returns -34018 and skips.
// The signed probe under /tmp/shh-mac-profile is the real round-trip.
func TestLiveICloudProbe(t *testing.T) {
	const (
		service = "shh-icloud-probe"
		account = "probe"
		value   = "probe-not-a-secret"
	)
	err := syncSet(service, account, value)
	if err != nil {
		st := syncStatus(-34018)
		if err.Error() == st.Error() || err == errSyncUnavailable {
			t.Skipf("sync unavailable: %v", err)
		}
		t.Fatalf("set: %v", err)
	}
	got, err := syncGet(service, account)
	if err != nil {
		_ = syncDelete(service, account)
		t.Fatalf("get: %v", err)
	}
	if got != value {
		_ = syncDelete(service, account)
		t.Fatalf("len %d", len(got))
	}
	if err := syncDelete(service, account); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

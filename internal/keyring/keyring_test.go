package keyring

import (
	"testing"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
)

type memStore struct {
	items  map[string]string
	getErr error
	setErr error
	delErr error
}

func newMem() *memStore {
	return &memStore{items: map[string]string{}}
}

func itemID(service, account string) string {
	return service + "\x00" + account
}

func (m *memStore) Get(service, account string) (string, error) {
	if m.getErr != nil {
		return "", m.getErr
	}
	v, ok := m.items[itemID(service, account)]
	if !ok {
		return "", errNotFound
	}
	return v, nil
}

func (m *memStore) Set(service, account, secret string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.items[itemID(service, account)] = secret
	return nil
}

func (m *memStore) Delete(service, account string) error {
	if m.delErr != nil {
		return m.delErr
	}
	id := itemID(service, account)
	if _, ok := m.items[id]; !ok {
		return errNotFound
	}
	delete(m.items, id)
	return nil
}

func useStores(t *testing.T, local, sync secretStore) {
	t.Helper()
	prevLocal, prevSync := localStore, syncStore
	localStore = local
	syncStore = sync
	t.Cleanup(func() {
		localStore = prevLocal
		syncStore = prevSync
	})
}

func TestStoreWritesLocalAndSync(t *testing.T) {
	local, sync := newMem(), newMem()
	useStores(t, local, sync)
	require.NoError(t, storeFor("alice", "probe-not-a-secret"))
	gotLocal, err := local.Get(keychainService, "alice")
	require.NoError(t, err)
	gotSync, err := sync.Get(keychainService, syncAccount)
	require.NoError(t, err)
	if gotLocal != "probe-not-a-secret" || gotSync != "probe-not-a-secret" {
		t.Fatalf("store mismatch local len %d sync len %d", len(gotLocal), len(gotSync))
	}
	_, err = sync.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
}

func TestStoreLeavesLocalWhenSyncUnavailable(t *testing.T) {
	local, sync := newMem(), newMem()
	sync.setErr = errSyncUnavailable
	useStores(t, local, sync)
	err := storeFor("alice", "probe-not-a-secret")
	require.ErrorIs(t, err, errSyncUnavailable)
	_, err = local.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
}

func TestGetCopiesSyncWhenLocalMissing(t *testing.T) {
	ident, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	secret := ident.String()
	t.Cleanup(func() { secret = "" })

	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, syncAccount, secret))
	useStores(t, local, sync)

	got, err := getFor("alice")
	require.NoError(t, err)
	if got != secret {
		t.Fatalf("get len %d", len(got))
	}
	copied, err := local.Get(keychainService, "alice")
	require.NoError(t, err)
	if copied != secret {
		t.Fatalf("copied len %d", len(copied))
	}
}

func TestGetCloudReplacesStaleLocal(t *testing.T) {
	older := mustIdentity(t)
	newer := mustIdentity(t)
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", older))
	require.NoError(t, sync.Set(keychainService, syncAccount, newer))
	useStores(t, local, sync)
	got, err := getFor("alice")
	require.NoError(t, err)
	if got != newer {
		t.Fatal("get kept the stale login item")
	}
	cached, err := local.Get(keychainService, "alice")
	require.NoError(t, err)
	if cached != newer {
		t.Fatal("login item stayed stale")
	}
}

func TestGetRejectsInvalidSyncValue(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, syncAccount, "probe-not-a-secret"))
	require.NoError(t, local.Set(keychainService, "alice", mustIdentity(t)))
	useStores(t, local, sync)
	_, err := getFor("alice")
	require.Error(t, err)
	cached, localErr := local.Get(keychainService, "alice")
	require.NoError(t, localErr)
	if cached == "probe-not-a-secret" {
		t.Fatal("invalid cloud value replaced the login item")
	}
}

func TestDeleteRemovesBoth(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", "probe-not-a-secret"))
	require.NoError(t, sync.Set(keychainService, syncAccount, "probe-not-a-secret"))
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	_, err := local.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
	mark, err := sync.Get(keychainService, syncAccount)
	require.NoError(t, err)
	if mark != revokedMark {
		t.Fatalf("cloud mark len %d", len(mark))
	}
	_, err = getFor("alice")
	require.Error(t, err)
}

func TestDeleteOfflineLeavesBoth(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", "probe-not-a-secret"))
	require.NoError(t, sync.Set(keychainService, syncAccount, "probe-not-a-secret"))
	sync.getErr = errSyncUnavailable
	useStores(t, local, sync)
	err := deleteFor("alice")
	require.ErrorIs(t, err, errSyncUnavailable)
	sync.getErr = nil
	_, err = local.Get(keychainService, "alice")
	require.NoError(t, err)
	got, err := sync.Get(keychainService, syncAccount)
	require.NoError(t, err)
	if got != "probe-not-a-secret" {
		t.Fatal("offline logout changed the cloud item")
	}
}

func TestDeleteSyncWhenLocalMissing(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, syncAccount, "probe-not-a-secret"))
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	mark, err := sync.Get(keychainService, syncAccount)
	require.NoError(t, err)
	if mark != revokedMark {
		t.Fatalf("cloud mark len %d", len(mark))
	}
}

func TestRevokeClearsOtherLoginOnGet(t *testing.T) {
	secret := mustIdentity(t)
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", secret))
	require.NoError(t, local.Set(keychainService, "bob", secret))
	require.NoError(t, sync.Set(keychainService, syncAccount, secret))
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	_, err := getFor("bob")
	require.Error(t, err)
	_, err = local.Get(keychainService, "bob")
	require.ErrorIs(t, err, errNotFound)
}

func TestAdoptPublishesLocalWhenCloudEmpty(t *testing.T) {
	secret := mustIdentity(t)
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", secret))
	useStores(t, local, sync)
	got, err := getFor("alice")
	require.NoError(t, err)
	if got != secret {
		t.Fatal("adopt dropped the login identity")
	}
	published, err := sync.Get(keychainService, syncAccount)
	require.NoError(t, err)
	if published != secret {
		t.Fatal("adopt did not publish")
	}
}

func mustIdentity(t *testing.T) string {
	t.Helper()
	ident, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return ident.String()
}

func TestDeleteMissing(t *testing.T) {
	useStores(t, newMem(), newMem())
	err := deleteFor("alice")
	require.ErrorIs(t, err, errNotFound)
}

func TestSyncStatus(t *testing.T) {
	require.NoError(t, syncStatus(0))
	require.ErrorIs(t, syncStatus(-25300), errNotFound)
	require.ErrorIs(t, syncStatus(-34018), errSyncUnavailable)
	err := syncStatus(-1)
	require.Error(t, err)
	require.False(t, errors.Is(err, errNotFound))
	require.False(t, errors.Is(err, errSyncUnavailable))
}

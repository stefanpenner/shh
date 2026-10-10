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
	gotSync, err := sync.Get(keychainService, "alice")
	require.NoError(t, err)
	if gotLocal != "probe-not-a-secret" || gotSync != "probe-not-a-secret" {
		t.Fatalf("store mismatch local len %d sync len %d", len(gotLocal), len(gotSync))
	}
}

func TestStoreSucceedsWhenSyncUnavailable(t *testing.T) {
	local, sync := newMem(), newMem()
	sync.setErr = errSyncUnavailable
	useStores(t, local, sync)
	require.NoError(t, storeFor("alice", "probe-not-a-secret"))
	got, err := local.Get(keychainService, "alice")
	require.NoError(t, err)
	if got != "probe-not-a-secret" {
		t.Fatalf("local len %d", len(got))
	}
}

func TestGetCopiesSyncWhenLocalMissing(t *testing.T) {
	ident, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	secret := ident.String()
	t.Cleanup(func() { secret = "" })

	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, "alice", secret))
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

func TestGetKeepsLocalWhenPresent(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", "local-probe"))
	require.NoError(t, sync.Set(keychainService, "alice", "sync-probe"))
	useStores(t, local, sync)
	got, err := getFor("alice")
	require.NoError(t, err)
	if got != "local-probe" {
		t.Fatalf("preferred sync over local, len %d", len(got))
	}
}

func TestGetRejectsInvalidSyncValue(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, "alice", "probe-not-a-secret"))
	useStores(t, local, sync)
	_, err := getFor("alice")
	require.Error(t, err)
	_, localErr := local.Get(keychainService, "alice")
	require.ErrorIs(t, localErr, errNotFound)
}

func TestDeleteRemovesBoth(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", "probe-not-a-secret"))
	require.NoError(t, sync.Set(keychainService, "alice", "probe-not-a-secret"))
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	_, err := local.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
	_, err = sync.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
}

func TestDeleteLocalOnlyWhenSyncUnavailable(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, local.Set(keychainService, "alice", "probe-not-a-secret"))
	sync.delErr = errSyncUnavailable
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	_, err := local.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
}

func TestDeleteSyncWhenLocalMissing(t *testing.T) {
	local, sync := newMem(), newMem()
	require.NoError(t, sync.Set(keychainService, "alice", "probe-not-a-secret"))
	useStores(t, local, sync)
	require.NoError(t, deleteFor("alice"))
	_, err := sync.Get(keychainService, "alice")
	require.ErrorIs(t, err, errNotFound)
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

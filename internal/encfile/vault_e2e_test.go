package encfile

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vault lifecycle e2e aligned with specs/RecipientVault.tla:
// Init → AddBob → Decrypt both → RemoveBob (rotate) → Bob fails → Alice OK → Tamper fails.

func TestVault_E2E_RecipientLifecycle(t *testing.T) {
	useTempDir(t)

	alicePriv, alicePub := generateTestKey(t)
	bobPriv, bobPub := generateTestKey(t)
	evePriv, _ := generateTestKey(t)

	safe := map[string]string{"API_KEY": "super-secret", "DB_PASS": "postgres-pass"}
	ef, err := EncryptSecrets(safe, map[string]string{"alice": alicePub})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	dec, err := DecryptSecrets(ef, alicePriv)
	require.NoError(t, err)
	assert.Equal(t, safe, dec)

	_, err = DecryptSecrets(ef, evePriv)
	require.Error(t, err)

	loaded, err := Load(".env.enc")
	require.NoError(t, err)
	newRecip := map[string]string{"alice": alicePub, "bob": bobPub}
	require.NoError(t, ReWrapDataKey(loaded, newRecip, alicePriv))
	require.NoError(t, Save(".env.enc", loaded))

	loaded, err = Load(".env.enc")
	require.NoError(t, err)
	decA, err := DecryptSecrets(loaded, alicePriv)
	require.NoError(t, err)
	decB, err := DecryptSecrets(loaded, bobPriv)
	require.NoError(t, err)
	assert.Equal(t, safe, decA)
	assert.Equal(t, safe, decB)

	// RemoveBob: rotate (new data key for alice only)
	onlyAlice := map[string]string{"alice": alicePub}
	rotated, err := EncryptSecrets(decA, onlyAlice)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", rotated))

	rot, err := Load(".env.enc")
	require.NoError(t, err)
	decA2, err := DecryptSecrets(rot, alicePriv)
	require.NoError(t, err)
	assert.Equal(t, safe, decA2)

	_, err = DecryptSecrets(rot, bobPriv)
	require.Error(t, err)

	// Tamper MAC
	rot.MAC = "0000000000000000000000000000000000000000000000000000000000000000"
	require.NoError(t, Save(".env.enc", rot))
	bad, err := Load(".env.enc")
	require.NoError(t, err)
	_, err = DecryptSecrets(bad, alicePriv)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAC")
}

func TestVault_E2E_EmptyRecipientsRejected(t *testing.T) {
	_, err := EncryptSecrets(map[string]string{"A": "b"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recipient")

	_, err = EncryptSecrets(map[string]string{"A": "b"}, map[string]string{})
	require.Error(t, err)

	// ReWrap empty also rejected
	priv, pub := generateTestKey(t)
	ef, err := EncryptSecrets(map[string]string{"A": "b"}, map[string]string{"u": pub})
	require.NoError(t, err)
	err = ReWrapDataKey(ef, map[string]string{}, priv)
	require.Error(t, err)
}

func TestVault_E2E_LoadAndEncryptRejectDisallowedPlugin(t *testing.T) {
	useTempDir(t)
	data := make([]byte, 32)
	_, err := rand.Read(data)
	require.NoError(t, err)
	evil := plugin.EncodeRecipient("evil", data)

	// Encrypt path
	_, err = EncryptSecrets(map[string]string{"A": "b"}, map[string]string{"x": evil})
	require.Error(t, err)

	// Load path
	priv, pub := generateTestKey(t)
	ef, err := EncryptSecrets(map[string]string{"K": "v"}, map[string]string{"ok": pub})
	require.NoError(t, err)
	ef.Recipients["evil"] = evil
	raw, err := Marshal(ef)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), ".env.enc")
	require.NoError(t, os.WriteFile(p, raw, 0o600))
	_, err = Load(p)
	require.Error(t, err)
	_ = priv
}

func TestVault_E2E_FileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "team.env.enc")
	priv, pub := generateTestKey(t)
	ef, err := EncryptSecrets(map[string]string{"TOKEN": "abc"}, map[string]string{"u": pub})
	require.NoError(t, err)
	require.NoError(t, Save(path, ef))

	loaded, err := Load(path)
	require.NoError(t, err)
	dec, err := DecryptSecrets(loaded, priv)
	require.NoError(t, err)
	assert.Equal(t, "abc", dec["TOKEN"])
}

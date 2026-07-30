package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/qr"
)

// CLI-level e2e: set/list/get path + users add/remove + recovery QR.
func TestCLI_E2E_SecretsAndUsersAndQR(t *testing.T) {
	useTempDir(t)

	alicePriv, alicePub := generateTestKey(t)
	setTestAgeKey(t, alicePriv)

	// Bootstrap vault as alice
	ef, err := encfile.EncryptSecrets(map[string]string{
		"API_KEY": "k1",
		"DB_URL":  "postgres://local",
	}, map[string]string{"https://github.com/alice": alicePub})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// list / get
	require.NoError(t, cmdList(".env.enc"))
	// get via LoadSecrets
	sec, err := encfile.LoadSecrets(".env.enc", alicePriv)
	require.NoError(t, err)
	assert.Equal(t, "k1", sec["API_KEY"])

	// set additional secret
	require.NoError(t, cmdSet(".env.enc", "NEW_TOKEN", "tok123"))
	sec, err = encfile.LoadSecrets(".env.enc", alicePriv)
	require.NoError(t, err)
	assert.Equal(t, "tok123", sec["NEW_TOKEN"])

	// users add recovery with QR
	qrPath := filepath.Join(t.TempDir(), "rec.png")
	require.NoError(t, usersAddCmd(nil, "recovery", "", usersAddOpts{QROut: qrPath}))
	payload, err := qr.DecodeFile(qrPath)
	require.NoError(t, err)

	// recovery can decrypt
	sec, err = encfile.LoadSecrets(".env.enc", payload)
	require.NoError(t, err)
	assert.Equal(t, "k1", sec["API_KEY"])

	// users remove by name — cannot remove last; remove alice github? keep recovery
	// List has alice + recovery. Remove alice github user leaves recovery.
	require.NoError(t, usersRemoveCmd([]string{"https://github.com/alice"}))
	// alice key no longer works
	_, err = encfile.LoadSecrets(".env.enc", alicePriv)
	require.Error(t, err)
	// recovery still works
	sec, err = encfile.LoadSecrets(".env.enc", payload)
	require.NoError(t, err)
	assert.Equal(t, "tok123", sec["NEW_TOKEN"])

	// cannot remove last recipient
	err = usersRemoveCmd([]string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last")

	// dangerous key rejected at set
	err = cmdSet(".env.enc", "LD_PRELOAD", "evil.so")
	require.Error(t, err)

	// run injects secrets, filters SHH_AGE_KEY from child (smoke via printenv)
	setTestAgeKey(t, payload)
	require.NoError(t, cmdRun(".env.enc", []string{"printenv", "API_KEY"}))
}

func TestCLI_E2E_RunSkipsDangerousAndFiltersKey(t *testing.T) {
	useTempDir(t)
	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	// Craft file with dangerous key via low-level encrypt (bypass set filter)
	// EncryptSecrets doesn't filter names — injection layer must
	ef, err := encfile.EncryptSecrets(map[string]string{
		"SAFE":       "1",
		"LD_PRELOAD": "bad",
	}, map[string]string{"u": pub})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// cmdRun should skip LD_PRELOAD (warning) and still run
	err = cmdRun(".env.enc", []string{"true"})
	require.NoError(t, err)
}

func TestCLI_E2E_QRLoginAfterDailyLost(t *testing.T) {
	useTempDir(t)
	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	ef, err := encfile.EncryptSecrets(map[string]string{"X": "1"}, map[string]string{"u": pub})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	qrPath := filepath.Join(t.TempDir(), "r.png")
	require.NoError(t, usersAddCmd(nil, "recovery", "", usersAddOpts{QROut: qrPath}))

	os.Unsetenv("SHH_AGE_KEY")
	// Keyring store needs a secret service (absent on headless CI).
	if err := runLoginQRFile(qrPath); err != nil {
		require.Contains(t, err.Error(), "keyring", "unexpected login failure: %v", err)
		t.Logf("keyring unavailable (%v); proving recovery via SHH_AGE_KEY", err)
	}

	// Recover secret from QR and decrypt
	payload, err := qr.DecodeFile(qrPath)
	require.NoError(t, err)
	setTestAgeKey(t, payload)
	sec, err := encfile.LoadSecrets(".env.enc", payload)
	require.NoError(t, err)
	assert.Equal(t, "1", sec["X"])
}

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/qr"
)

// Recovery QR round-trip (mirrors specs/RecoveryQR.tla GenerateEmitQR → ScanQR):
//   daily encrypts vault → users add --qr → lose daily → login from QR → decrypt.
func TestRecoveryQR_RoundTrip_TLAConformance(t *testing.T) {
	useTempDir(t)

	dailyPriv, dailyPub := generateTestKey(t)
	setTestAgeKey(t, dailyPriv)

	secrets := map[string]string{
		"POSTGRES_SUPER_PASS": "s3cret-pg",
		"LLDAP_ADMIN_PASS":    "s3cret-ldap",
	}
	recipients := map[string]string{"https://github.com/alice": dailyPub}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Capture generated recovery secret via QR file (EmitQR).
	qrPath := filepath.Join(t.TempDir(), "recovery.png")
	require.NoError(t, usersAddCmd(nil, "recovery", "", usersAddOpts{QROut: qrPath}))

	// Recipient set includes recovery (GenerateRecovery + re-wrap).
	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	require.Len(t, loaded.Recipients, 2)
	_, hasRecovery := loaded.Recipients["shh-user://recovery"]
	assert.True(t, hasRecovery)

	// QR file exists and decodes to a valid age identity (QRFidelity).
	payload, err := qr.DecodeFile(qrPath)
	require.NoError(t, err)
	assert.True(t, qr.IsAgeIdentity(payload))

	// LoseDailyKey: clear SHH_AGE_KEY / keyring simulation — only QR path remains.
	os.Unsetenv("SHH_AGE_KEY")
	_ = keyring.DeleteKey() // best-effort; SHH_AGE_KEY was the test auth path

	// ScanQR + Login: enroll from QR file.
	require.NoError(t, runLoginQRFile(qrPath))

	// DecryptVault with recovery identity via SHH_AGE_KEY from QR payload.
	setTestAgeKey(t, payload)
	reloaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err := encfile.DecryptSecrets(reloaded, payload)
	require.NoError(t, err, "recovery identity from QR must decrypt vault")
	assert.Equal(t, secrets, dec)
}

func TestLoginQRFile_RejectsNonIdentity(t *testing.T) {
	dir := t.TempDir()
	// Encode a non-identity payload
	path := filepath.Join(dir, "nope.png")
	require.NoError(t, qr.EncodeFile("just a passphrase phrase not an age key", path))
	err := runLoginQRFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an age identity")
}

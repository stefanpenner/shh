package cli

import (
	"os"
	"path/filepath"
	"testing"

	goqrcode "github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/qr"
)

// E2E recovery path (specs/RecoveryQR.tla GenerateEmitQR → LoseDaily → ScanQR):
// daily encrypts → users add --qr → wipe daily auth → login from QR → decrypt.
func TestRecoveryQR_E2E_RoundTrip(t *testing.T) {
	useTempDir(t)

	dailyPriv, dailyPub := generateTestKey(t)
	setTestAgeKey(t, dailyPriv)

	secrets := map[string]string{
		"POSTGRES_SUPER_PASS": "s3cret-pg",
		"LLDAP_ADMIN_PASS":    "s3cret-ldap",
		"PGBACKUP_S3_SECRET":  "s3cret-garage",
	}
	recipients := map[string]string{"https://github.com/alice": dailyPub}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	qrPath := filepath.Join(t.TempDir(), "recovery.png")
	require.NoError(t, usersAddCmd(nil, "recovery", "", usersAddOpts{QROut: qrPath}))

	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	require.Len(t, loaded.Recipients, 2)

	// QR file mode 0600
	st, err := os.Stat(qrPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	payload, err := qr.DecodeFile(qrPath)
	require.NoError(t, err)
	require.True(t, qr.IsExtractableAgeSecret(payload))

	// LoseDaily
	os.Unsetenv("SHH_AGE_KEY")
	_ = keyring.DeleteKey()

	// ScanQR — keyring store needs a secret service (absent on headless CI).
	// Crypto recovery still holds: decode QR → identity decrypts vault.
	if err := runLoginQRFile(qrPath); err != nil {
		require.Contains(t, err.Error(), "keyring", "unexpected login failure: %v", err)
		t.Logf("keyring unavailable (%v); proving recovery via SHH_AGE_KEY", err)
	}
	setTestAgeKey(t, payload)
	reloaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err := encfile.DecryptSecrets(reloaded, payload)
	require.NoError(t, err)
	assert.Equal(t, secrets, dec)

	// Daily key no longer required; recovery alone works after RemoveDaily equivalent:
	// re-encrypt only for recovery and decrypt.
	onlyRecovery := map[string]string{"shh-user://recovery": loaded.Recipients["shh-user://recovery"]}
	// Need recovery private to re-encrypt — use payload
	newEf, err := encfile.EncryptSecrets(secrets, onlyRecovery)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", newEf))
	dec2, err := encfile.DecryptSecrets(newEf, payload)
	require.NoError(t, err)
	assert.Equal(t, secrets, dec2)
}

func TestLoginQRFile_RejectsEvilPayloads(t *testing.T) {
	dir := t.TempDir()

	// URL quishing
	urlPath := filepath.Join(dir, "phish.png")
	code, err := goqrcode.New("https://evil.example/steal-keys", goqrcode.Medium)
	require.NoError(t, err)
	require.NoError(t, code.WriteFile(256, urlPath))
	err = runLoginQRFile(urlPath)
	require.Error(t, err)

	// Random non-identity phrase
	phrasePath := filepath.Join(dir, "phrase.png")
	require.NoError(t, encodeArbitraryQR(t, "correct horse battery staple but not age", phrasePath))
	err = runLoginQRFile(phrasePath)
	require.Error(t, err)

	// Missing file
	err = runLoginQRFile(filepath.Join(dir, "nope.png"))
	require.Error(t, err)

	// Truncated / garbage
	garbage := filepath.Join(dir, "garbage.png")
	require.NoError(t, os.WriteFile(garbage, []byte{0x00, 0x01, 0xff}, 0o600))
	err = runLoginQRFile(garbage)
	require.Error(t, err)
}

func TestUsersAddQR_RejectsWhenKeyProvided(t *testing.T) {
	useTempDir(t)
	dailyPriv, dailyPub := generateTestKey(t)
	setTestAgeKey(t, dailyPriv)
	ef, err := encfile.EncryptSecrets(map[string]string{"A": "b"}, map[string]string{"u": dailyPub})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	_, otherPub := generateTestKey(t)
	// --key provided: no secret generated → QR note, no panic
	err = usersAddCmd(nil, "other", otherPub, usersAddOpts{QR: true, QROut: filepath.Join(t.TempDir(), "x.png")})
	require.NoError(t, err)
}

func encodeArbitraryQR(t *testing.T, payload, path string) error {
	t.Helper()
	code, err := goqrcode.New(payload, goqrcode.Medium)
	if err != nil {
		return err
	}
	return code.WriteFile(256, path)
}

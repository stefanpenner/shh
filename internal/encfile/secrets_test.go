package encfile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/crypto"
)

func TestIntegration_EncryptDecrypt(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{
		"SECRET":  "hello",
		"API_KEY": "sk-123",
	}
	recipients := map[string]string{"testuser": pubKey}

	ef, err := EncryptSecrets(secrets, recipients)
	require.NoError(t, err)

	err = Save(".env.enc", ef)
	require.NoError(t, err)

	// Verify encrypted file doesn't contain plaintext
	data, _ := os.ReadFile(".env.enc")
	assert.NotContains(t, string(data), "hello")
	assert.NotContains(t, string(data), "sk-123")

	assert.Contains(t, string(data), "[recipients]")
	assert.Contains(t, string(data), "[secrets]")
	assert.Contains(t, string(data), "version = 2")

	// Decrypt
	loaded, err := Load(".env.enc")
	require.NoError(t, err)

	decrypted, err := DecryptSecrets(loaded, privKey)
	require.NoError(t, err)
	assert.Equal(t, "hello", decrypted["SECRET"])
	assert.Equal(t, "sk-123", decrypted["API_KEY"])
}

func TestIntegration_MultiRecipient(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	recipients := map[string]string{"user1": pub1, "user2": pub2}
	secrets := map[string]string{"SHARED_SECRET": "42"}

	ef, err := EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	// Decrypt with key2
	loaded, _ := Load(".env.enc")
	decrypted, err := DecryptSecrets(loaded, priv2)
	require.NoError(t, err)
	assert.Equal(t, "42", decrypted["SHARED_SECRET"])

	// Decrypt with key1
	loaded, _ = Load(".env.enc")
	decrypted, err = DecryptSecrets(loaded, priv1)
	require.NoError(t, err)
	assert.Equal(t, "42", decrypted["SHARED_SECRET"])
}

func TestIntegration_ReWrapDataKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	priv3, pub3 := generateTestKey(t)

	secrets := map[string]string{"UPDATE_TEST": "secret"}
	ef, err := EncryptSecrets(secrets, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	newRecipients := map[string]string{
		"user1": pub1,
		"user2": pub2,
		"user3": pub3,
	}
	err = ReWrapDataKey(loaded, newRecipients, priv1)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", loaded))

	reloaded, _ := Load(".env.enc")
	decrypted, err := DecryptSecrets(reloaded, priv3)
	require.NoError(t, err)
	assert.Equal(t, "secret", decrypted["UPDATE_TEST"])
}

func TestIntegration_SpecialChars(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)

	secrets := map[string]string{
		"PASSWORD": "p@ss w0rd!#$%",
		"URL":      "https://example.com?foo=bar&baz=1",
		"QUOTES":   `value with "quotes" and 'singles'`,
		"NEWLINES": "line1\nline2\nline3",
	}
	recipients := map[string]string{"testuser": pubKey}

	ef, err := EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	decrypted, err := DecryptSecrets(loaded, privKey)
	require.NoError(t, err)

	assert.Equal(t, secrets["PASSWORD"], decrypted["PASSWORD"])
	assert.Equal(t, secrets["URL"], decrypted["URL"])
	assert.Equal(t, secrets["QUOTES"], decrypted["QUOTES"])
	assert.Equal(t, secrets["NEWLINES"], decrypted["NEWLINES"])
}

func TestIntegration_MACTampering(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)

	ef.MAC = "0000000000000000000000000000000000000000000000000000000000000000"
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	_, err = DecryptSecrets(loaded, privKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MAC verification failed")
}

func TestIntegration_MACDetectsRecipientTamperingInFile(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	loaded.Recipients["eve"] = "age1evexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	require.NoError(t, Save(".env.enc", loaded))

	reloaded, _ := Load(".env.enc")
	_, err = DecryptSecrets(reloaded, privKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MAC verification failed")
}

func TestIntegration_EmptySecrets(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)

	ef, err := EncryptSecrets(map[string]string{}, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	decrypted, err := DecryptSecrets(loaded, privKey)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestIntegration_UnauthorizedRecipientCannotDecrypt(t *testing.T) {
	useTempDir(t)

	_, pub1 := generateTestKey(t)
	priv2, _ := generateTestKey(t)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := EncryptSecrets(secrets, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, _ := Load(".env.enc")
	_, err = DecryptSecrets(loaded, priv2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in the recipients list")
}

func TestV1_LoadAndDecrypt(t *testing.T) {
	useTempDir(t)

	priv, pub := generateTestKey(t)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)

	wrapped, err := crypto.WrapDataKeyForRecipient(dataKey, pub)
	require.NoError(t, err)

	enc, err := crypto.EncryptValue(dataKey, "SECRET", "hello")
	require.NoError(t, err)

	recipients := map[string]string{"testuser": pub}
	secrets := map[string]string{"SECRET": enc}
	mac := crypto.ComputeMACv1(dataKey, 1, wrapped, recipients, secrets)

	content := fmt.Sprintf("version = 1\nmac = %q\ndata_key = %q\n\n[recipients]\ntestuser = %q\n\n[secrets]\nSECRET = %q\n",
		mac, wrapped, pub, enc)
	require.NoError(t, os.WriteFile(".env.enc", []byte(content), 0600))

	ef, err := Load(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, 1, ef.Version)

	decrypted, err := DecryptSecrets(ef, priv)
	require.NoError(t, err)
	assert.Equal(t, "hello", decrypted["SECRET"])
}

func TestIntegration_UsersRemoveRotatesDataKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"user1": pub1, "user2": pub2}
	ef, err := EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	oldWrappedKey := ef.WrappedKeys["user1"]

	// Remove user2 by re-encrypting with only user1
	loaded, _ := Load(".env.enc")
	decrypted, err := DecryptSecrets(loaded, priv1)
	require.NoError(t, err)
	newRecipients := map[string]string{"user1": pub1}
	newEf, err := EncryptSecrets(decrypted, newRecipients)
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", newEf))

	assert.NotEqual(t, oldWrappedKey, newEf.WrappedKeys["user1"])

	oldDK, err := crypto.UnwrapDataKey(oldWrappedKey, priv1)
	require.NoError(t, err)
	for _, v := range newEf.Secrets {
		_, err := crypto.DecryptValue(oldDK, "SECRET", v)
		assert.Error(t, err, "old data key should not decrypt values encrypted with new key")
	}

	// Removed user cannot decrypt
	reloaded, _ := Load(".env.enc")
	_, err = DecryptSecrets(reloaded, priv2)
	assert.Error(t, err)
}

func TestWrappedKeys_AddRecipient_MinimalChange(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	ef, err := EncryptSecrets(map[string]string{"SECRET": "hello"}, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, err := Load(".env.enc")
	require.NoError(t, err)
	newRecipients := map[string]string{"user1": pub1, "user2": pub2}
	err = ReWrapDataKey(loaded, newRecipients, priv1)
	require.NoError(t, err)

	assert.Contains(t, loaded.WrappedKeys, "user1")
	assert.Contains(t, loaded.WrappedKeys, "user2")
}

func TestDefaultRecipients(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	recipients, err := DefaultRecipients(identity.String(), "alice")
	require.NoError(t, err)
	assert.Len(t, recipients, 1)
	assert.Equal(t, identity.Recipient().String(), recipients["https://github.com/alice"])
}

// --- Plaintext tests ---

func TestParsePlaintext(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"single", "FOO=bar", map[string]string{"FOO": "bar"}},
		{"multiple", "FOO=bar\nBAZ=qux", map[string]string{"FOO": "bar", "BAZ": "qux"}},
		{"with comments", "# comment\nFOO=bar\n\nBAZ=qux", map[string]string{"FOO": "bar", "BAZ": "qux"}},
		{"value with equals", "FOO=a=b=c", map[string]string{"FOO": "a=b=c"}},
		{"empty value", "FOO=", map[string]string{"FOO": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePlaintext(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatPlaintext(t *testing.T) {
	secrets := map[string]string{"ZZZ": "3", "AAA": "1", "MMM": "2"}
	out := FormatPlaintext(secrets)
	assert.Equal(t, "AAA=1\nMMM=2\nZZZ=3\n", out)
}

func TestLoadSecrets_FromPlaintext(t *testing.T) {
	dir := useTempDir(t)

	plaintext := "FOO=bar\nBAZ=qux\n"
	plaintextPath := filepath.Join(dir, ".env.test")
	require.NoError(t, os.WriteFile(plaintextPath, []byte(plaintext), 0600))

	os.Setenv("SHH_PLAINTEXT", plaintextPath)
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	secrets, err := LoadSecrets(".env.enc", "")
	require.NoError(t, err)
	assert.Equal(t, "bar", secrets["FOO"])
	assert.Equal(t, "qux", secrets["BAZ"])
}

func TestLoadSecrets_FromEncrypted(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)

	os.Unsetenv("SHH_PLAINTEXT")

	secrets := map[string]string{"SECRET": "encrypted_value"}
	ef, err := EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, Save(".env.enc", ef))

	loaded, err := LoadSecrets(".env.enc", privKey)
	require.NoError(t, err)
	assert.Equal(t, "encrypted_value", loaded["SECRET"])
}

func TestLoadSecrets_PlaintextFileNotFound(t *testing.T) {
	os.Setenv("SHH_PLAINTEXT", "/nonexistent/path/.env")
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	_, err := LoadSecrets(".env.enc", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read plaintext file")
}

func FuzzParsePlaintext(f *testing.F) {
	f.Add("FOO=bar\nBAZ=qux")
	f.Add("")
	f.Add("# comment\nKEY=value")
	f.Add("NO_EQUALS_SIGN")
	f.Fuzz(func(t *testing.T, input string) {
		ParsePlaintext(input) //nolint:errcheck -- fuzz: only checking for panics, not errors
	})
}

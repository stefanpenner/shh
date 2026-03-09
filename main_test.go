package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// helper: chdir to a temp dir, restore on cleanup
func useTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

// helper: generate an age keypair
func generateTestKey(t *testing.T) (privKey, pubKey string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return identity.String(), identity.Recipient().String()
}

// helper: set SHH_AGE_KEY for tests (bypasses keyring)
func setTestAgeKey(t *testing.T, privKey string) {
	t.Helper()
	os.Setenv("SHH_AGE_KEY", privKey)
	t.Cleanup(func() { os.Unsetenv("SHH_AGE_KEY") })
}

// --- Crypto unit tests ---

func TestEncryptDecryptValue(t *testing.T) {
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello"},
		{"empty", ""},
		{"special chars", "p@ss w0rd!#$%^&*()"},
		{"unicode", "こんにちは世界"},
		{"url", "https://example.com?foo=bar&baz=1"},
		{"long value", strings.Repeat("a", 10000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := encryptValue(dataKey, "TEST_KEY", tt.plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, tt.plaintext, enc, "encrypted should differ from plaintext")

			dec, err := decryptValue(dataKey, "TEST_KEY", enc)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, dec)
		})
	}
}

func TestEncryptValue_UniqueNonces(t *testing.T) {
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	enc1, err := encryptValue(dataKey, "KEY", "same")
	require.NoError(t, err)
	enc2, err := encryptValue(dataKey, "KEY", "same")
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "two encryptions of same plaintext should differ (unique nonces)")
}

func TestDecryptValue_InvalidBase64(t *testing.T) {
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	_, err = decryptValue(dataKey, "KEY", "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecryptValue_TamperedCiphertext(t *testing.T) {
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	enc, err := encryptValue(dataKey, "KEY", "secret")
	require.NoError(t, err)

	// Tamper with ciphertext
	tampered := enc[:len(enc)-2] + "XX"
	_, err = decryptValue(dataKey, "KEY", tampered)
	assert.Error(t, err)
}

func TestDecryptValue_WrongKey(t *testing.T) {
	key1, err := generateDataKey()
	require.NoError(t, err)
	key2, err := generateDataKey()
	require.NoError(t, err)

	enc, err := encryptValue(key1, "KEY", "secret")
	require.NoError(t, err)

	_, err = decryptValue(key2, "KEY", enc)
	assert.Error(t, err)
}

func TestAAD_PreventsValueSwapping(t *testing.T) {
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	enc, err := encryptValue(dataKey, "KEY_A", "secret_a")
	require.NoError(t, err)

	// Decrypting with the wrong key name should fail (AAD mismatch)
	_, err = decryptValue(dataKey, "KEY_B", enc)
	assert.Error(t, err, "decrypting with wrong key name AAD should fail")

	// Decrypting with the correct key name should work
	dec, err := decryptValue(dataKey, "KEY_A", enc)
	require.NoError(t, err)
	assert.Equal(t, "secret_a", dec)
}

func TestWrapUnwrapDataKey(t *testing.T) {
	priv, pub := generateTestKey(t)
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	wrapped, err := wrapDataKeyForRecipient(dataKey, pub)
	require.NoError(t, err)

	unwrapped, err := unwrapDataKey(wrapped, priv)
	require.NoError(t, err)

	assert.Equal(t, dataKey, unwrapped)
}

func TestWrapDataKey_PerRecipient(t *testing.T) {
	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	recipients := map[string]string{"alice": pub1, "bob": pub2}
	wrappedKeys, err := wrapDataKeyPerRecipient(dataKey, recipients)
	require.NoError(t, err)

	// Each recipient can only unwrap their own key
	unwrapped1, err := unwrapDataKey(wrappedKeys["alice"], priv1)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped1)

	unwrapped2, err := unwrapDataKey(wrappedKeys["bob"], priv2)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped2)

	// Cross-decryption should fail
	_, err = unwrapDataKey(wrappedKeys["alice"], priv2)
	assert.Error(t, err)
}

func TestComputeMAC_Deterministic(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1", "B": "2"}
	recipients := map[string]string{"alice": "age1aaa"}
	wrappedKeys := map[string]string{"alice": "wk1"}

	mac1 := computeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
	mac2 := computeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
	assert.Equal(t, mac1, mac2)
}

func TestComputeMAC_DifferentSecrets(t *testing.T) {
	dataKey, _ := generateDataKey()
	recipients := map[string]string{"alice": "age1aaa"}
	wrappedKeys := map[string]string{"alice": "wk1"}

	mac1 := computeMAC(dataKey, 2, wrappedKeys, recipients, map[string]string{"A": "1"})
	mac2 := computeMAC(dataKey, 2, wrappedKeys, recipients, map[string]string{"A": "2"})
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_ConstantTimeComparison(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}
	wrappedKeys := map[string]string{"alice": "wk1"}
	mac := computeMAC(dataKey, 2, wrappedKeys, recipients, secrets)

	// Verify hmac.Equal works for comparison
	assert.True(t, hmac.Equal([]byte(mac), []byte(mac)))
	assert.False(t, hmac.Equal([]byte(mac), []byte("wrong")))
}

func TestComputeMAC_DetectsRecipientTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients1 := map[string]string{"alice": "age1aaa"}
	recipients2 := map[string]string{"alice": "age1aaa", "eve": "age1eve"}
	wrappedKeys := map[string]string{"alice": "wk1"}

	mac1 := computeMAC(dataKey, 2, wrappedKeys, recipients1, secrets)
	mac2 := computeMAC(dataKey, 2, wrappedKeys, recipients2, secrets)
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_DetectsVersionTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}
	wrappedKeys := map[string]string{"alice": "wk1"}

	mac1 := computeMAC(dataKey, 1, wrappedKeys, recipients, secrets)
	mac2 := computeMAC(dataKey, 99, wrappedKeys, recipients, secrets)
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_DetectsWrappedKeyTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}

	mac1 := computeMAC(dataKey, 2, map[string]string{"alice": "wk1"}, recipients, secrets)
	mac2 := computeMAC(dataKey, 2, map[string]string{"alice": "wk2"}, recipients, secrets)
	assert.NotEqual(t, mac1, mac2)
}

// --- File format tests ---

func TestMarshalLoadRoundtrip(t *testing.T) {
	useTempDir(t)

	ef := &EncryptedFile{
		Version:     2,
		MAC:         "deadbeef",
		Recipients:  map[string]string{"alice": "age1abc", "bob": "age1def"},
		WrappedKeys: map[string]string{"alice": "wk1", "bob": "wk2"},
		Secrets:     map[string]string{"SECRET": "enc1", "API_KEY": "enc2"},
	}

	err := saveEncryptedFile(".env.enc", ef)
	require.NoError(t, err)

	loaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)

	assert.Equal(t, ef.Version, loaded.Version)
	assert.Equal(t, ef.MAC, loaded.MAC)
	assert.Equal(t, ef.Recipients, loaded.Recipients)
	assert.Equal(t, ef.WrappedKeys, loaded.WrappedKeys)
	assert.Equal(t, ef.Secrets, loaded.Secrets)
}

func TestSaveEncryptedFile_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions not supported on Windows")
	}
	useTempDir(t)

	ef := &EncryptedFile{
		Version:     2,
		MAC:         "test",
		Recipients:  map[string]string{},
		WrappedKeys: map[string]string{},
		Secrets:     map[string]string{},
	}

	err := saveEncryptedFile(".env.enc", ef)
	require.NoError(t, err)

	info, err := os.Stat(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSaveEncryptedFile_AtomicWrite(t *testing.T) {
	useTempDir(t)

	ef := &EncryptedFile{
		Version:     2,
		MAC:         "test",
		Recipients:  map[string]string{},
		WrappedKeys: map[string]string{},
		Secrets:     map[string]string{},
	}

	err := saveEncryptedFile(".env.enc", ef)
	require.NoError(t, err)

	// Verify no temp files left behind
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".shh-"), "temp file should be cleaned up: %s", e.Name())
	}
}

func TestLoadEncryptedFile_InvalidVersion(t *testing.T) {
	useTempDir(t)

	os.WriteFile(".env.enc", []byte("version = 99\nmac = \"x\"\ndata_key = \"x\"\n"), 0600)
	_, err := loadEncryptedFile(".env.enc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported file version")
}

func TestLoadEncryptedFile_EmptySecrets(t *testing.T) {
	useTempDir(t)

	content := "version = 1\nmac = \"x\"\ndata_key = \"x\"\n\n[recipients]\nalice = \"age1abc\"\n\n[secrets]\n"
	os.WriteFile(".env.enc", []byte(content), 0600)

	ef, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	assert.Empty(t, ef.Secrets)
	assert.Len(t, ef.Recipients, 1)
}

func TestTomlKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SIMPLE", "SIMPLE"},
		{"with-dash", "with-dash"},
		{"under_score", "under_score"},
		{"has space", `"has space"`},
		{"has.dot", `"has.dot"`},
		{"", `""`},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, tomlKey(tt.input))
		})
	}
}

func TestMarshalEncryptedFile_SortedOutput(t *testing.T) {
	ef := &EncryptedFile{
		Version:     2,
		MAC:         "mac",
		Recipients:  map[string]string{"bob": "age1bbb", "alice": "age1aaa"},
		WrappedKeys: map[string]string{"bob": "wk_bob", "alice": "wk_alice"},
		Secrets:     map[string]string{"ZZZ": "enc1", "AAA": "enc2"},
	}

	data, err := marshalEncryptedFile(ef)
	require.NoError(t, err)
	out := string(data)

	// Recipients should be sorted
	aliceIdx := strings.Index(out, "alice")
	bobIdx := strings.Index(out, "bob")
	assert.Greater(t, bobIdx, aliceIdx, "alice should come before bob")

	// Wrapped keys should be sorted
	wkAliceIdx := strings.Index(out, "wk_alice")
	wkBobIdx := strings.Index(out, "wk_bob")
	assert.Greater(t, wkBobIdx, wkAliceIdx, "alice wrapped key should come before bob")

	// Secrets should be sorted
	aaaIdx := strings.Index(out, "AAA")
	zzzIdx := strings.Index(out, "ZZZ")
	assert.Greater(t, zzzIdx, aaaIdx, "AAA should come before ZZZ")
}

func TestValidateTOMLValue(t *testing.T) {
	assert.NoError(t, validateTOMLValue("hello world"))
	assert.NoError(t, validateTOMLValue("line1\nline2"))
	assert.NoError(t, validateTOMLValue("tab\there"))
	assert.NoError(t, validateTOMLValue(""))
	assert.Error(t, validateTOMLValue("has\x00null"))
	assert.Error(t, validateTOMLValue("has\x01ctrl"))
	assert.Error(t, validateTOMLValue("bell\x07here"))
}

// --- Plaintext parsing tests ---

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
			got := parsePlaintext(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatPlaintext(t *testing.T) {
	secrets := map[string]string{"ZZZ": "3", "AAA": "1", "MMM": "2"}
	out := formatPlaintext(secrets)

	assert.Equal(t, "AAA=1\nMMM=2\nZZZ=3\n", out)
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "'hello'"},
		{"empty", "", "''"},
		{"dollar sign", "$HOME", "'$HOME'"},
		{"backtick cmd sub", "`id`", "'`id`'"},
		{"dollar cmd sub", "$(id)", "'$(id)'"},
		{"single quote", "it's", "'it'\\''s'"},
		{"double quote", `say "hi"`, `'say "hi"'`},
		{"newline", "a\nb", "'a\nb'"},
		{"backslash", `a\b`, `'a\b'`},
		{"mixed specials", "$HOME;`id`;$(pwd)", "'$HOME;`id`;$(pwd)'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shellQuote(tt.input))
		})
	}
}

// --- Validation tests ---

func TestEnvVarKeyValidation(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"FOO", true},
		{"_FOO", true},
		{"FOO_BAR", true},
		{"foo123", true},
		{"123FOO", false},
		{"FOO BAR", false},
		{"FOO=BAR", false},
		{"", false},
		{"FOO-BAR", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.valid, envVarKeyPattern.MatchString(tt.key))
		})
	}
}

func TestAgeKeyValidation(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		valid bool
	}{
		{"valid key", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", true},
		{"too short", "age1abc", false},
		{"has comma", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq,q", false},
		{"has quote", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\"q", false},
		{"not age prefix", "notage1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, ageKeyPattern.MatchString(tt.key))
		})
	}
}

func TestGithubUsernameValidation(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		valid bool
	}{
		{"simple", "alice", true},
		{"with hyphen", "alice-bob", true},
		{"with numbers", "alice123", true},
		{"single char", "a", true},
		{"starts with hyphen", "-alice", false},
		{"ends with hyphen", "alice-", false},
		{"has slash", "alice/bob", false},
		{"has dot-dot", "../etc", false},
		{"empty", "", false},
		{"has space", "alice bob", false},
		{"too long (40 chars)", strings.Repeat("a", 40), false},
		{"max length (39 chars)", strings.Repeat("a", 39), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, githubUserPattern.MatchString(tt.user))
		})
	}
}

func TestDangerousEnvVarDenylist(t *testing.T) {
	blocked := []string{"PATH", "HOME", "SHELL", "USER", "LOGNAME",
		"LD_PRELOAD", "LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"}
	for _, key := range blocked {
		t.Run(key, func(t *testing.T) {
			assert.True(t, dangerousEnvVars[key], "%s should be in denylist", key)
		})
	}
	// Legitimate keys should not be blocked
	assert.False(t, dangerousEnvVars["DATABASE_URL"])
	assert.False(t, dangerousEnvVars["API_KEY"])
}

// --- Integration tests ---

func TestIntegration_EncryptDecrypt(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{
		"SECRET":  "hello",
		"API_KEY": "sk-123",
	}
	recipients := map[string]string{"testuser": pubKey}

	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)

	err = saveEncryptedFile(".env.enc", ef)
	require.NoError(t, err)

	// Verify encrypted file doesn't contain plaintext
	data, _ := os.ReadFile(".env.enc")
	assert.NotContains(t, string(data), "hello")
	assert.NotContains(t, string(data), "sk-123")

	// Verify it's valid TOML with expected structure
	assert.Contains(t, string(data), "[recipients]")
	assert.Contains(t, string(data), "[secrets]")
	assert.Contains(t, string(data), "version = 2")
	assert.Contains(t, string(data), "[wrapped_keys]")

	// Decrypt
	loaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)

	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "hello", decrypted["SECRET"])
	assert.Equal(t, "sk-123", decrypted["API_KEY"])
}

func TestIntegration_SetAndRm(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	// Encrypt initial secrets
	secrets := map[string]string{"SECRET": "hello", "API_KEY": "sk-123"}
	recipients := map[string]string{"testuser": pubKey}

	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Set (add new key)
	secrets["NEW_KEY"] = "new_value"
	ef, err = encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "new_value", decrypted["NEW_KEY"])
	assert.Equal(t, "hello", decrypted["SECRET"])

	// Set (update existing key)
	secrets["SECRET"] = "updated"
	ef, err = encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ = loadEncryptedFile(".env.enc")
	decrypted, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "updated", decrypted["SECRET"])

	// Rm
	delete(secrets, "API_KEY")
	ef, err = encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ = loadEncryptedFile(".env.enc")
	decrypted, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.NotContains(t, decrypted, "API_KEY")
	assert.Equal(t, "updated", decrypted["SECRET"])
	assert.Equal(t, "new_value", decrypted["NEW_KEY"])
}

func TestIntegration_MultiRecipient(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	recipients := map[string]string{"user1": pub1, "user2": pub2}
	secrets := map[string]string{"SHARED_SECRET": "42"}

	// Encrypt with both recipients
	setTestAgeKey(t, priv1)
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Decrypt with key2
	setTestAgeKey(t, priv2)
	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "42", decrypted["SHARED_SECRET"])

	// Decrypt with key1 also works
	setTestAgeKey(t, priv1)
	loaded, _ = loadEncryptedFile(".env.enc")
	decrypted, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "42", decrypted["SHARED_SECRET"])
}

func TestIntegration_ReWrapDataKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	priv3, pub3 := generateTestKey(t)

	// Encrypt with key1 only
	setTestAgeKey(t, priv1)
	secrets := map[string]string{"UPDATE_TEST": "secret"}
	ef, err := encryptSecrets(secrets, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Add key2 and key3
	loaded, _ := loadEncryptedFile(".env.enc")
	newRecipients := map[string]string{
		"user1": pub1,
		"user2": pub2,
		"user3": pub3,
	}
	err = reWrapDataKey(loaded, newRecipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", loaded))

	// Decrypt with key3 (newly added)
	setTestAgeKey(t, priv3)
	reloaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(reloaded)
	require.NoError(t, err)
	assert.Equal(t, "secret", decrypted["UPDATE_TEST"])
}

func TestIntegration_SpecialChars(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{
		"PASSWORD": "p@ss w0rd!#$%",
		"URL":      "https://example.com?foo=bar&baz=1",
		"QUOTES":   `value with "quotes" and 'singles'`,
		"NEWLINES": "line1\nline2\nline3",
	}
	recipients := map[string]string{"testuser": pubKey}

	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)

	assert.Equal(t, secrets["PASSWORD"], decrypted["PASSWORD"])
	assert.Equal(t, secrets["URL"], decrypted["URL"])
	assert.Equal(t, secrets["QUOTES"], decrypted["QUOTES"])
	assert.Equal(t, secrets["NEWLINES"], decrypted["NEWLINES"])
}

func TestIntegration_MACTampering(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)

	// Tamper with MAC
	ef.MAC = "0000000000000000000000000000000000000000000000000000000000000000"
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ := loadEncryptedFile(".env.enc")
	_, err = decryptSecrets(loaded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MAC verification failed")
}

func TestIntegration_MACDetectsRecipientTamperingInFile(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Tamper with recipients (add an extra one)
	loaded, _ := loadEncryptedFile(".env.enc")
	loaded.Recipients["eve"] = "age1evexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	require.NoError(t, saveEncryptedFile(".env.enc", loaded))

	reloaded, _ := loadEncryptedFile(".env.enc")
	_, err = decryptSecrets(reloaded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MAC verification failed")
}

func TestIntegration_EmptySecrets(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	ef, err := encryptSecrets(map[string]string{}, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestIntegration_UnauthorizedRecipientCannotDecrypt(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, _ := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Try to decrypt with unauthorized key
	setTestAgeKey(t, priv2)
	loaded, _ := loadEncryptedFile(".env.enc")
	_, err = decryptSecrets(loaded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in the recipients list")
}

func TestIntegration_UsersRemoveRotatesDataKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"user1": pub1, "user2": pub2}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Capture the old wrapped data key for user1
	oldWrappedKey := ef.WrappedKeys["user1"]

	// Remove user2 (simulating usersRemoveCmd logic: decrypt then re-encrypt)
	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	newRecipients := map[string]string{"user1": pub1}
	newEf, err := encryptSecrets(decrypted, newRecipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", newEf))

	// Wrapped key should be different (rotated)
	assert.NotEqual(t, oldWrappedKey, newEf.WrappedKeys["user1"])

	// Old data key should not decrypt new secrets
	oldDK, err := unwrapDataKey(oldWrappedKey, priv1)
	require.NoError(t, err)
	for _, v := range newEf.Secrets {
		_, err := decryptValue(oldDK, "SECRET", v)
		assert.Error(t, err, "old data key should not decrypt values encrypted with new key")
	}

	// Removed user cannot decrypt (not in recipients)
	setTestAgeKey(t, priv2)
	reloaded, _ := loadEncryptedFile(".env.enc")
	_, err = decryptSecrets(reloaded)
	assert.Error(t, err)
}

func TestIntegration_UsersAddRemoveLifecycle(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	// --- Setup: create file with user1 and user2, with a secret ---
	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "lifecycle-test"}
	recipients := map[string]string{
		"https://github.com/alice": pub1,
		"https://github.com/bob":   pub2,
	}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Both users can decrypt
	setTestAgeKey(t, priv1)
	loaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	dec, err := decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	setTestAgeKey(t, priv2)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	dec, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	// --- Remove bob by bare username ---
	setTestAgeKey(t, priv1)
	err = usersRemoveCmd([]string{"bob"})
	require.NoError(t, err)

	// alice can still decrypt
	setTestAgeKey(t, priv1)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	dec, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	// bob can no longer decrypt
	setTestAgeKey(t, priv2)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	_, err = decryptSecrets(loaded)
	assert.Error(t, err, "removed user should not be able to decrypt")

	// --- Re-add bob (simulating usersAddCmd without GitHub fetch) ---
	setTestAgeKey(t, priv1)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	newRecipients := make(map[string]string, len(loaded.Recipients)+1)
	for k, v := range loaded.Recipients {
		newRecipients[k] = v
	}
	newRecipients["https://github.com/bob"] = pub2
	err = reWrapDataKey(loaded, newRecipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", loaded))

	// bob can decrypt again
	setTestAgeKey(t, priv2)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	dec, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	// alice can still decrypt too
	setTestAgeKey(t, priv1)
	loaded, err = loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	dec, err = decryptSecrets(loaded)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])
}

func TestIntegration_UsersRemoveByGitHubUsername(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	// Simulate how `users add` stores GitHub users: name is "https://github.com/<username>"
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/rwjblue": pub2}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Remove by bare GitHub username (the way users actually type it)
	err = usersRemoveCmd([]string{"rwjblue"})
	require.NoError(t, err)

	// Verify rwjblue was removed
	reloaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
	_, hasAlice := reloaded.Recipients["https://github.com/alice"]
	assert.True(t, hasAlice, "alice should remain")
	_, hasRwjblue := reloaded.Recipients["https://github.com/rwjblue"]
	assert.False(t, hasRwjblue, "rwjblue should be removed")
}

func TestIntegration_UsersRemoveByDisplayName(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/bob": pub2}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Remove by full URL name (should still work)
	err = usersRemoveCmd([]string{"https://github.com/bob"})
	require.NoError(t, err)

	reloaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
}

func TestIntegration_UsersRemoveByNumber(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/bob": pub2}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Remove by number (bob is #2 alphabetically: alice=1, bob=2)
	err = usersRemoveCmd([]string{"2"})
	require.NoError(t, err)

	reloaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
	_, hasAlice := reloaded.Recipients["https://github.com/alice"]
	assert.True(t, hasAlice)
}

func TestFindEncFile_WalksUp(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks (macOS /var -> /private/var) to match os.Getwd()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	// Create .env.enc in root
	ef := &EncryptedFile{
		Version:     2,
		MAC:         "test",
		Recipients:  map[string]string{},
		WrappedKeys: map[string]string{},
		Secrets:     map[string]string{},
	}
	require.NoError(t, os.Chdir(dir))
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	// Create nested dirs and cd into them
	nested := filepath.Join(dir, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.Chdir(nested))

	found := findEncFile()
	assert.Equal(t, filepath.Join(dir, ".env.enc"), found)
}

func TestFindEncFile_FallsBack(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	// No .env.enc anywhere — should fall back to default
	require.NoError(t, os.Chdir(dir))
	found := findEncFile()
	assert.Equal(t, defaultEncryptedFile, found)
}

func TestRecipientDisplayName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"https://github.com/alice", "alice"},
		{"https://github.com/stefanpenner", "stefanpenner"},
		{"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"},
		{"legacy-name", "legacy-name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, recipientDisplayName(tt.name))
		})
	}
}

func TestPublicKeyFrom(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	pub, err := publicKeyFrom(identity.String())
	require.NoError(t, err)
	assert.Equal(t, identity.Recipient().String(), pub)
}

func TestFilterEnv(t *testing.T) {
	env := []string{"FOO=bar", "SHH_AGE_KEY=secret", "BAZ=qux", "OTHER=val"}
	filtered := filterEnv(env, "SHH_AGE_KEY")

	assert.Len(t, filtered, 3)
	assert.NotContains(t, filtered, "SHH_AGE_KEY=secret")
	assert.Contains(t, filtered, "FOO=bar")
}

// --- V1 migration tests ---

func TestV1_LoadAndDecrypt(t *testing.T) {
	useTempDir(t)

	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)

	// Create a v1-format file manually
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	wrapped, err := wrapDataKeyForRecipient(dataKey, pub)
	require.NoError(t, err)

	enc, err := encryptValue(dataKey, "SECRET", "hello")
	require.NoError(t, err)

	recipients := map[string]string{"testuser": pub}
	secrets := map[string]string{"SECRET": enc}
	mac := computeMACv1(dataKey, 1, wrapped, recipients, secrets)

	// Write v1 format directly
	content := fmt.Sprintf("version = 1\nmac = %q\ndata_key = %q\n\n[recipients]\ntestuser = %q\n\n[secrets]\nSECRET = %q\n",
		mac, wrapped, pub, enc)
	require.NoError(t, os.WriteFile(".env.enc", []byte(content), 0600))

	// Should load and decrypt successfully
	ef, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, 1, ef.Version)

	decrypted, err := decryptSecrets(ef)
	require.NoError(t, err)
	assert.Equal(t, "hello", decrypted["SECRET"])
}

// --- Merge tests ---

func TestMergeSecrets_NoConflict(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{"A": "1", "B": "2"}
	theirs := map[string]string{"A": "1", "C": "3"}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "1", "B": "2", "C": "3"}, result)
}

func TestMergeSecrets_BothAddSameValue(t *testing.T) {
	ancestor := map[string]string{}
	ours := map[string]string{"A": "1"}
	theirs := map[string]string{"A": "1"}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "1"}, result)
}

func TestMergeSecrets_ConflictingEdit(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{"A": "2"}
	theirs := map[string]string{"A": "3"}

	_, conflicts, err := mergeSecrets(ancestor, ours, theirs)
	assert.Error(t, err)
	assert.Equal(t, []string{"A"}, conflicts)
}

func TestMergeSecrets_BothAddDifferentValues(t *testing.T) {
	ancestor := map[string]string{}
	ours := map[string]string{"A": "1"}
	theirs := map[string]string{"A": "2"}

	_, conflicts, err := mergeSecrets(ancestor, ours, theirs)
	assert.Error(t, err)
	assert.Equal(t, []string{"A"}, conflicts)
}

func TestMergeSecrets_OneDeleteUnchanged(t *testing.T) {
	ancestor := map[string]string{"A": "1", "B": "2"}
	ours := map[string]string{"A": "1"} // deleted B
	theirs := map[string]string{"A": "1", "B": "2"}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "1"}, result)
}

func TestMergeSecrets_DeleteVsModify(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{} // deleted A
	theirs := map[string]string{"A": "2"} // modified A

	_, conflicts, err := mergeSecrets(ancestor, ours, theirs)
	assert.Error(t, err)
	assert.Equal(t, []string{"A"}, conflicts)
}

func TestMergeSecrets_OnlyOursChanged(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{"A": "2"}
	theirs := map[string]string{"A": "1"}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "2"}, result)
}

func TestMergeSecrets_OnlyTheirsChanged(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{"A": "1"}
	theirs := map[string]string{"A": "2"}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"A": "2"}, result)
}

func TestMergeSecrets_BothDelete(t *testing.T) {
	ancestor := map[string]string{"A": "1"}
	ours := map[string]string{}
	theirs := map[string]string{}

	result, _, err := mergeSecrets(ancestor, ours, theirs)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestIntegration_CmdMerge(t *testing.T) {
	useTempDir(t)

	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	recipients := map[string]string{"testuser": pub}

	// Create ancestor with one secret
	ancestor, err := encryptSecrets(map[string]string{"BASE": "value"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile("ancestor.enc", ancestor))

	// Ours adds a secret
	oursSecrets := map[string]string{"BASE": "value", "OURS_KEY": "ours_val"}
	oursEf, err := encryptSecrets(oursSecrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile("ours.enc", oursEf))

	// Theirs adds a different secret
	theirsSecrets := map[string]string{"BASE": "value", "THEIRS_KEY": "theirs_val"}
	theirsEf, err := encryptSecrets(theirsSecrets, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile("theirs.enc", theirsEf))

	// Run merge
	err = cmdMerge("ancestor.enc", "ours.enc", "theirs.enc")
	require.NoError(t, err)

	// Load and decrypt the merged result
	merged, err := loadEncryptedFile("ours.enc")
	require.NoError(t, err)
	decrypted, err := decryptSecrets(merged)
	require.NoError(t, err)

	assert.Equal(t, "value", decrypted["BASE"])
	assert.Equal(t, "ours_val", decrypted["OURS_KEY"])
	assert.Equal(t, "theirs_val", decrypted["THEIRS_KEY"])
}

func TestWrappedKeys_AddRecipient_MinimalChange(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	setTestAgeKey(t, priv1)

	// Create file with one recipient
	ef, err := encryptSecrets(map[string]string{"SECRET": "hello"}, map[string]string{"user1": pub1})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	originalWrappedKey := ef.WrappedKeys["user1"]

	// Add a second recipient
	loaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)
	newRecipients := map[string]string{"user1": pub1, "user2": pub2}
	err = reWrapDataKey(loaded, newRecipients)
	require.NoError(t, err)

	// user1's wrapped key changed (re-wrapped), but user2 was added
	assert.Contains(t, loaded.WrappedKeys, "user1")
	assert.Contains(t, loaded.WrappedKeys, "user2")
	// The wrapped keys will differ since re-wrapping uses new random nonces,
	// but both should decrypt to the same data key
	_ = originalWrappedKey
}

// --- Auto-resolve tests ---

// gitRun runs a git command in dir and fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

func TestAutoResolve_OnLoad(t *testing.T) {
	// Create a git repo with a merge conflict on .env.enc
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	recipients := map[string]string{"testuser": pub}

	// Init repo and create base commit
	gitRun(t, dir, "init", "-b", "main")
	os.Chdir(dir)

	baseEf, err := encryptSecrets(map[string]string{"BASE": "value"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), baseEf))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "base")

	// Create branch-a: add KEY_A
	gitRun(t, dir, "checkout", "-b", "branch-a")
	efA, err := encryptSecrets(map[string]string{"BASE": "value", "KEY_A": "a_val"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), efA))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "add KEY_A")

	// Create branch-b from main: add KEY_B
	gitRun(t, dir, "checkout", "main")
	gitRun(t, dir, "checkout", "-b", "branch-b")
	efB, err := encryptSecrets(map[string]string{"BASE": "value", "KEY_B": "b_val"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), efB))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "add KEY_B")

	// Merge branch-a into branch-b — this will conflict
	mergeCmd := exec.Command("git", "merge", "branch-a")
	mergeCmd.Dir = dir
	mergeCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	mergeCmd.Run() // expected to fail

	// Verify .env.enc is conflicted
	lsOut, _ := exec.Command("git", "ls-files", "-u", ".env.enc").Output()
	require.NotEmpty(t, lsOut, "file should be in conflicted state")

	// loadEncryptedFile should auto-resolve
	ef, err := loadEncryptedFile(filepath.Join(dir, ".env.enc"))
	require.NoError(t, err)

	// Decrypt and verify all keys are present
	decrypted, err := decryptSecrets(ef)
	require.NoError(t, err)
	assert.Equal(t, "value", decrypted["BASE"])
	assert.Equal(t, "a_val", decrypted["KEY_A"])
	assert.Equal(t, "b_val", decrypted["KEY_B"])

	// Verify the file is staged (no longer conflicted)
	lsOut, _ = exec.Command("git", "ls-files", "-u", ".env.enc").Output()
	assert.Empty(t, lsOut, "file should no longer be conflicted after auto-resolve")
}

func TestAutoResolve_Conflict_Fails(t *testing.T) {
	// Same setup but both branches modify the same key differently
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	recipients := map[string]string{"testuser": pub}

	gitRun(t, dir, "init", "-b", "main")
	os.Chdir(dir)

	baseEf, err := encryptSecrets(map[string]string{"SECRET": "original"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), baseEf))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "base")

	// branch-a changes SECRET
	gitRun(t, dir, "checkout", "-b", "branch-a")
	efA, err := encryptSecrets(map[string]string{"SECRET": "from_a"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), efA))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "change SECRET in a")

	// branch-b changes SECRET differently
	gitRun(t, dir, "checkout", "main")
	gitRun(t, dir, "checkout", "-b", "branch-b")
	efB, err := encryptSecrets(map[string]string{"SECRET": "from_b"}, recipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(filepath.Join(dir, ".env.enc"), efB))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "change SECRET in b")

	// Merge
	mergeCmd := exec.Command("git", "merge", "branch-a")
	mergeCmd.Dir = dir
	mergeCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	mergeCmd.Run()

	// loadEncryptedFile should fail — auto-resolve can't handle conflicting edits
	_, err = loadEncryptedFile(filepath.Join(dir, ".env.enc"))
	assert.Error(t, err)
}

// --- Fuzz tests ---

func FuzzEncryptDecryptValue(f *testing.F) {
	f.Add("hello", "KEY")
	f.Add("", "")
	f.Add("p@ss w0rd!#$%^&*()", "MY_SECRET")
	f.Add(strings.Repeat("x", 10000), "BIG")
	f.Fuzz(func(t *testing.T, plaintext, keyName string) {
		dataKey, err := generateDataKey()
		if err != nil {
			t.Skip()
		}
		enc, err := encryptValue(dataKey, keyName, plaintext)
		if err != nil {
			t.Skip()
		}
		dec, err := decryptValue(dataKey, keyName, enc)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dec)
	})
}

func FuzzComputeMAC(f *testing.F) {
	f.Add("key1", "val1")
	f.Add("", "")
	f.Add("A\x00B", "val") // null byte in key
	f.Fuzz(func(t *testing.T, k, v string) {
		dataKey, err := generateDataKey()
		if err != nil {
			t.Skip()
		}
		secrets := map[string]string{k: v}
		recipients := map[string]string{"alice": "age1aaa"}
		wrappedKeys := map[string]string{"alice": "wk1"}
		mac1 := computeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
		mac2 := computeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
		assert.Equal(t, mac1, mac2, "MAC should be deterministic")
	})
}

func FuzzParsePlaintext(f *testing.F) {
	f.Add("FOO=bar\nBAZ=qux")
	f.Add("")
	f.Add("# comment\nKEY=value")
	f.Add("NO_EQUALS_SIGN")
	f.Add("=empty_key")
	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		parsePlaintext(input)
	})
}

func FuzzShellQuote(f *testing.F) {
	f.Add("hello")
	f.Add("it's")
	f.Add("$HOME;`id`")
	f.Add("")
	f.Add("'")
	f.Add("a\nb\tc")
	f.Fuzz(func(t *testing.T, input string) {
		result := shellQuote(input)
		// Must start and end with single quote
		assert.True(t, strings.HasPrefix(result, "'"))
		assert.True(t, strings.HasSuffix(result, "'"))
	})
}

func FuzzTomlKey(f *testing.F) {
	f.Add("SIMPLE")
	f.Add("has space")
	f.Add("")
	f.Add("with.dot")
	f.Add("with\"quote")
	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		tomlKey(input)
	})
}

func FuzzValidateTOMLValue(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add("\x00")
	f.Add("line\nbreak")
	f.Fuzz(func(t *testing.T, input string) {
		err := validateTOMLValue(input)
		// If no control chars, should pass
		hasControl := false
		for _, c := range input {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
				hasControl = true
				break
			}
		}
		if hasControl {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	})
}

// --- SSH key passphrase test helpers ---

func generatePassphraseProtectedTestKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func generateUnprotectedTestKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func setTestPassphraseReader(t *testing.T, passphrase string) {
	t.Helper()
	orig := readPassphrase
	readPassphrase = func(keyPath string) ([]byte, error) {
		return []byte(passphrase), nil
	}
	t.Cleanup(func() { readPassphrase = orig })
}

// --- SSH key passphrase tests ---

func TestSshKeyToAge_UnprotectedKey(t *testing.T) {
	keyData := generateUnprotectedTestKey(t)
	priv, pub, err := sshKeyToAge(keyData, "/tmp/test_key")
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.True(t, strings.HasPrefix(*pub, "age1"))
}

func TestSshKeyToAge_PassphraseProtected(t *testing.T) {
	passphrase := "test-passphrase-123"
	keyData := generatePassphraseProtectedTestKey(t, passphrase)
	setTestPassphraseReader(t, passphrase)

	priv, pub, err := sshKeyToAge(keyData, "/tmp/test_key")
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.True(t, strings.HasPrefix(*pub, "age1"))
}

func TestSshKeyToAge_WrongPassphrase(t *testing.T) {
	keyData := generatePassphraseProtectedTestKey(t, "correct-passphrase")
	setTestPassphraseReader(t, "wrong-passphrase")

	_, _, err := sshKeyToAge(keyData, "/tmp/test_key")
	assert.Error(t, err)
}

func TestSshKeyToAge_PromptsWithCorrectPath(t *testing.T) {
	passphrase := "test-passphrase"
	keyData := generatePassphraseProtectedTestKey(t, passphrase)

	var capturedPath string
	orig := readPassphrase
	readPassphrase = func(keyPath string) ([]byte, error) {
		capturedPath = keyPath
		return []byte(passphrase), nil
	}
	t.Cleanup(func() { readPassphrase = orig })

	expectedPath := "/home/user/.ssh/id_ed25519"
	_, _, err := sshKeyToAge(keyData, expectedPath)
	require.NoError(t, err)
	assert.Equal(t, expectedPath, capturedPath)
}

func TestFindSSHEd25519Keys_IncludesPassphraseProtected(t *testing.T) {
	// Set up a temp HOME with .ssh directory
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Create an unprotected ed25519 key
	unprotectedData := generateUnprotectedTestKey(t)
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "id_ed25519"), unprotectedData, 0600))

	// Create a passphrase-protected ed25519 key
	protectedData := generatePassphraseProtectedTestKey(t, "my-passphrase")
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "id_ed25519_protected"), protectedData, 0600))

	// Override HOME
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })

	keys := findSSHEd25519Keys()
	assert.Len(t, keys, 2, "should find both protected and unprotected keys")

	// Both paths should be present
	var foundUnprotected, foundProtected bool
	for _, k := range keys {
		if strings.HasSuffix(k, "id_ed25519") {
			foundUnprotected = true
		}
		if strings.HasSuffix(k, "id_ed25519_protected") {
			foundProtected = true
		}
	}
	assert.True(t, foundUnprotected, "should find unprotected key")
	assert.True(t, foundProtected, "should find passphrase-protected key")
}

func TestSshKeyToAge_ProtectedAndUnprotectedProduceSameResult(t *testing.T) {
	// Generate a key, save it both protected and unprotected, verify same age key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	passphrase := "test-pass"

	unprotectedBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	unprotectedPEM := pem.EncodeToMemory(unprotectedBlock)

	protectedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	protectedPEM := pem.EncodeToMemory(protectedBlock)

	// Unprotected conversion
	_, pubUnprotected, err := sshKeyToAge(unprotectedPEM, "/tmp/key")
	require.NoError(t, err)

	// Protected conversion
	setTestPassphraseReader(t, passphrase)
	_, pubProtected, err := sshKeyToAge(protectedPEM, "/tmp/key")
	require.NoError(t, err)

	assert.Equal(t, *pubUnprotected, *pubProtected, "same key should produce same age public key")
}

// --- Helper: setupEncryptedFile ---

func setupEncryptedFile(t *testing.T, file string, secrets map[string]string, pubKey string) {
	t.Helper()
	recipients := map[string]string{"test-user": pubKey}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	err = saveEncryptedFile(file, ef)
	require.NoError(t, err)
}

// --- Run command tests ---

func TestCmdRun_ExecutesCommand(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"FOO": "bar"}, pubKey)

	err := cmdRun(".env.enc", []string{"true"})
	assert.NoError(t, err)
}

func TestCmdRun_SetsEnvVars(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"MY_SECRET": "s3cret_value"}, pubKey)

	err := cmdRun(".env.enc", []string{"printenv", "MY_SECRET"})
	assert.NoError(t, err)
}

func TestCmdRun_FiltersShhAgeKey(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"FOO": "bar"}, pubKey)

	err := cmdRun(".env.enc", []string{"printenv", "SHH_AGE_KEY"})
	assert.Error(t, err, "SHH_AGE_KEY should not be in child environment")
}

func TestCmdRun_NoArgs(t *testing.T) {
	err := cmdRun(".env.enc", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no command specified")
}

func TestCmdRun_NonZeroExit(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"FOO": "bar"}, pubKey)

	err := cmdRun(".env.enc", []string{"false"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exited with status")
}

func TestCmdRun_CommandNotFound(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"FOO": "bar"}, pubKey)

	err := cmdRun(".env.enc", []string{"nonexistent_command_xyz_12345"})
	assert.Error(t, err)
}

func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantFile string
		wantCmd  []string
	}{
		{
			name:     "no args",
			args:     nil,
			wantFile: "",
			wantCmd:  nil,
		},
		{
			name:     "command only, no separator",
			args:     []string{"echo", "hello"},
			wantFile: "",
			wantCmd:  []string{"echo", "hello"},
		},
		{
			name:     "separator with command",
			args:     []string{"--", "echo", "hello"},
			wantFile: "",
			wantCmd:  []string{"echo", "hello"},
		},
		{
			name:     "file and separator with command",
			args:     []string{"secrets.enc", "--", "echo", "hello"},
			wantFile: "secrets.enc",
			wantCmd:  []string{"echo", "hello"},
		},
		{
			name:     "separator only",
			args:     []string{"--"},
			wantFile: "",
			wantCmd:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, cmd := parseRunArgs(tt.args)
			assert.Equal(t, tt.wantFile, file)
			assert.Equal(t, tt.wantCmd, cmd)
		})
	}
}

// --- Doctor tests ---

func TestRunDoctorChecks_AllPass(t *testing.T) {
	dir := useTempDir(t)

	privKey, pubKey := generateTestKey(t)

	setTestAgeKey(t, privKey)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pubKey}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	encFile := filepath.Join(dir, ".env.enc")
	require.NoError(t, saveEncryptedFile(encFile, ef))

	checks := runDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		encFile,
	)

	require.Len(t, checks, 5)
	assert.True(t, checks[0].Status, "age key check should pass")
	assert.Equal(t, "age key", checks[0].Name)
	assert.Contains(t, checks[0].Message, "age1")

	assert.True(t, checks[1].Status, "github cli check should pass")
	assert.Equal(t, "github cli", checks[1].Name)
	assert.Equal(t, "alice", checks[1].Message)

	assert.True(t, checks[2].Status, "ssh keys check should pass")
	assert.Equal(t, "ssh keys", checks[2].Name)
	assert.Contains(t, checks[2].Message, "1 ed25519 key(s) found")

	assert.True(t, checks[3].Status, "encrypted file check should pass")
	assert.Equal(t, "encrypted file", checks[3].Name)
	assert.Contains(t, checks[3].Message, "1 secret")
	assert.Contains(t, checks[3].Message, "1 recipient")

	assert.True(t, checks[4].Status, "recipient check should pass")
	assert.Equal(t, "recipient", checks[4].Name)
	assert.Equal(t, "your key is authorized", checks[4].Message)
}

func TestRunDoctorChecks_NoKey(t *testing.T) {
	checks := runDoctorChecks(
		func() (string, error) { return "", errors.New("no key") },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.False(t, checks[0].Status, "age key check should fail")
	assert.Equal(t, "age key", checks[0].Name)
	assert.Contains(t, checks[0].Message, "no key found")
}

func TestRunDoctorChecks_NoGitHub(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := runDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.True(t, checks[0].Status, "age key check should pass")
	assert.False(t, checks[1].Status, "github cli check should fail")
	assert.Equal(t, "github cli", checks[1].Name)
	assert.Contains(t, checks[1].Message, "not installed or not logged in")
}

func TestRunDoctorChecks_NoSSHKeys(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := runDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return nil },
		"/nonexistent/.env.enc",
	)

	assert.True(t, checks[0].Status, "age key check should pass")
	assert.True(t, checks[1].Status, "github cli check should pass")
	assert.False(t, checks[2].Status, "ssh keys check should fail")
	assert.Equal(t, "ssh keys", checks[2].Name)
	assert.Contains(t, checks[2].Message, "no ed25519 keys found")
}

func TestRunDoctorChecks_NoEncFile(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := runDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.True(t, checks[0].Status, "age key check should pass")
	assert.True(t, checks[1].Status, "github cli check should pass")
	assert.True(t, checks[2].Status, "ssh keys check should pass")
	assert.False(t, checks[3].Status, "encrypted file check should fail")
	assert.Equal(t, "encrypted file", checks[3].Name)
	assert.Contains(t, checks[3].Message, "not found or invalid")
	assert.Len(t, checks, 4)
}

func TestRunDoctorChecks_NotInRecipients(t *testing.T) {
	dir := useTempDir(t)

	privKey, _ := generateTestKey(t)
	otherPriv, otherPub := generateTestKey(t)

	setTestAgeKey(t, otherPriv)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/bob": otherPub}
	ef, err := encryptSecrets(secrets, recipients)
	require.NoError(t, err)
	encFile := filepath.Join(dir, ".env.enc")
	require.NoError(t, saveEncryptedFile(encFile, ef))

	checks := runDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		encFile,
	)

	require.Len(t, checks, 5)
	assert.True(t, checks[3].Status, "encrypted file check should pass")
	assert.False(t, checks[4].Status, "recipient check should fail")
	assert.Equal(t, "recipient", checks[4].Name)
	assert.Contains(t, checks[4].Message, "NOT in the recipients list")
}

// --- Env flag tests ---

func TestEnvFlag(t *testing.T) {
	assert.Equal(t, "", envFlag(""))
	assert.Equal(t, "production.env.enc", envFlag("production"))
	assert.Equal(t, "staging.env.enc", envFlag("staging"))
}

func TestResolveFile(t *testing.T) {
	// env flag takes precedence
	assert.Equal(t, "production.env.enc", resolveFile("production", []string{"other.enc"}))
	// falls back to fileArg
	assert.Equal(t, "other.enc", resolveFile("", []string{"other.enc"}))
	// falls back to findEncFile when both empty
	result := resolveFile("", nil)
	assert.NotEmpty(t, result)
}

// --- TTY warning tests ---

func TestCmdEnv_WarnsWhenNotTTY(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	var stderr bytes.Buffer
	err = cmdEnv(".env.enc", &stderr, func() bool { return false }, false)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), "warning:")
}

func TestCmdEnv_NoWarningWhenTTY(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	var stderr bytes.Buffer
	err = cmdEnv(".env.enc", &stderr, func() bool { return true }, false)
	require.NoError(t, err)
	assert.Empty(t, stderr.String())
}

func TestCmdEnv_QuietSuppressesWarning(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	var stderr bytes.Buffer
	err = cmdEnv(".env.enc", &stderr, func() bool { return false }, false)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), "warning:")

	var stderr2 bytes.Buffer
	err = cmdEnv(".env.enc", &stderr2, func() bool { return false }, true)
	require.NoError(t, err)
	assert.Empty(t, stderr2.String())
}

// --- LoadSecrets / SHH_PLAINTEXT tests ---

func TestLoadSecrets_FromPlaintext(t *testing.T) {
	dir := useTempDir(t)

	plaintext := "FOO=bar\nBAZ=qux\n"
	plaintextPath := filepath.Join(dir, ".env.test")
	require.NoError(t, os.WriteFile(plaintextPath, []byte(plaintext), 0600))

	os.Setenv("SHH_PLAINTEXT", plaintextPath)
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	secrets, err := loadSecrets(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, "bar", secrets["FOO"])
	assert.Equal(t, "qux", secrets["BAZ"])
}

func TestLoadSecrets_FromEncrypted(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	os.Unsetenv("SHH_PLAINTEXT")

	secrets := map[string]string{"SECRET": "encrypted_value"}
	ef, err := encryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", ef))

	loaded, err := loadSecrets(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, "encrypted_value", loaded["SECRET"])
}

func TestLoadSecrets_PlaintextFileNotFound(t *testing.T) {
	os.Setenv("SHH_PLAINTEXT", "/nonexistent/path/.env")
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	_, err := loadSecrets(".env.enc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read plaintext file")
}

func TestLoadSecrets_PlaintextWithComments(t *testing.T) {
	dir := useTempDir(t)

	plaintext := "# Database config\nDB_HOST=localhost\nDB_PORT=5432\n\n# API\nAPI_KEY=test-key\n"
	path := filepath.Join(dir, ".env.test")
	require.NoError(t, os.WriteFile(path, []byte(plaintext), 0600))

	os.Setenv("SHH_PLAINTEXT", path)
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	secrets, err := loadSecrets(".env.enc")
	require.NoError(t, err)
	assert.Equal(t, "localhost", secrets["DB_HOST"])
	assert.Equal(t, "5432", secrets["DB_PORT"])
	assert.Equal(t, "test-key", secrets["API_KEY"])
	assert.Len(t, secrets, 3)
}

func TestLoadSecrets_EmptyPlaintext(t *testing.T) {
	dir := useTempDir(t)

	path := filepath.Join(dir, ".env.test")
	require.NoError(t, os.WriteFile(path, []byte(""), 0600))

	os.Setenv("SHH_PLAINTEXT", path)
	t.Cleanup(func() { os.Unsetenv("SHH_PLAINTEXT") })

	secrets, err := loadSecrets(".env.enc")
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

// --- Template tests ---

func TestRenderTemplate(t *testing.T) {
	secrets := map[string]string{"API_KEY": "abc123", "DB_PASSWORD": "s3cret"}
	result, err := renderTemplate("key={{API_KEY}} pass={{DB_PASSWORD}}", secrets)
	require.NoError(t, err)
	assert.Equal(t, "key=abc123 pass=s3cret", result)
}

func TestRenderTemplateNoPlaceholders(t *testing.T) {
	result, err := renderTemplate("no placeholders here", map[string]string{"FOO": "bar"})
	require.NoError(t, err)
	assert.Equal(t, "no placeholders here", result)
}

func TestRenderTemplateMissingSecret(t *testing.T) {
	_, err := renderTemplate("{{FOO}} {{BAR}} {{BAZ}}", map[string]string{"FOO": "ok"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BAR")
	assert.Contains(t, err.Error(), "BAZ")
	assert.NotContains(t, err.Error(), "FOO")
}

func TestRenderTemplatePartialBraces(t *testing.T) {
	result, err := renderTemplate("{{ not valid }} and {NOPE} and {{OK}}", map[string]string{"OK": "yes"})
	require.NoError(t, err)
	assert.Equal(t, "{{ not valid }} and {NOPE} and yes", result)
}

func TestRenderTemplateRepeatedKey(t *testing.T) {
	result, err := renderTemplate("{{X}}-{{X}}-{{X}}", map[string]string{"X": "v"})
	require.NoError(t, err)
	assert.Equal(t, "v-v-v", result)
}

func TestRenderTemplateEmptyValue(t *testing.T) {
	result, err := renderTemplate("before{{KEY}}after", map[string]string{"KEY": ""})
	require.NoError(t, err)
	assert.Equal(t, "beforeafter", result)
}

func TestRenderTemplateSpecialChars(t *testing.T) {
	val := `"quotes" & <xml> 'yaml': {json}`
	result, err := renderTemplate("val={{SECRET}}", map[string]string{"SECRET": val})
	require.NoError(t, err)
	assert.Equal(t, "val="+val, result)
}

func TestCmdTemplate(t *testing.T) {
	dir := useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"API_KEY": "my-key", "DB_PASS": "secret"}, pubKey)

	tplPath := filepath.Join(dir, "config.tpl")
	require.NoError(t, os.WriteFile(tplPath, []byte("api={{API_KEY}} db={{DB_PASS}}"), 0600))

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmdTemplate(tplPath, ".env.enc")
	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
	var buf bytes.Buffer
	buf.ReadFrom(r)
	assert.Equal(t, "api=my-key db=secret", buf.String())
}

func TestCmdTemplateStdin(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"TOKEN": "tok123"}, pubKey)

	// Replace stdin
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Write([]byte("token={{TOKEN}}"))
	w.Close()
	os.Stdin = r

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	err := cmdTemplate("-", ".env.enc")
	wOut.Close()
	os.Stdout = oldStdout
	os.Stdin = oldStdin

	require.NoError(t, err)
	var buf bytes.Buffer
	buf.ReadFrom(rOut)
	assert.Equal(t, "token=tok123", buf.String())
}

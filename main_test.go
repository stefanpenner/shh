package main

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	wrapped, err := wrapDataKey(dataKey, []string{pub})
	require.NoError(t, err)

	unwrapped, err := unwrapDataKey(wrapped, priv)
	require.NoError(t, err)

	assert.Equal(t, dataKey, unwrapped)
}

func TestWrapDataKey_MultiRecipient(t *testing.T) {
	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)
	dataKey, err := generateDataKey()
	require.NoError(t, err)

	wrapped, err := wrapDataKey(dataKey, []string{pub1, pub2})
	require.NoError(t, err)

	// Both recipients can unwrap
	unwrapped1, err := unwrapDataKey(wrapped, priv1)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped1)

	unwrapped2, err := unwrapDataKey(wrapped, priv2)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped2)
}

func TestComputeMAC_Deterministic(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1", "B": "2"}
	recipients := map[string]string{"alice": "age1aaa"}

	mac1 := computeMAC(dataKey, 1,"dk", recipients, secrets)
	mac2 := computeMAC(dataKey, 1,"dk", recipients, secrets)
	assert.Equal(t, mac1, mac2)
}

func TestComputeMAC_DifferentSecrets(t *testing.T) {
	dataKey, _ := generateDataKey()
	recipients := map[string]string{"alice": "age1aaa"}

	mac1 := computeMAC(dataKey, 1,"dk", recipients, map[string]string{"A": "1"})
	mac2 := computeMAC(dataKey, 1,"dk", recipients, map[string]string{"A": "2"})
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_ConstantTimeComparison(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}
	mac := computeMAC(dataKey, 1,"dk", recipients, secrets)

	// Verify hmac.Equal works for comparison
	assert.True(t, hmac.Equal([]byte(mac), []byte(mac)))
	assert.False(t, hmac.Equal([]byte(mac), []byte("wrong")))
}

func TestComputeMAC_DetectsRecipientTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients1 := map[string]string{"alice": "age1aaa"}
	recipients2 := map[string]string{"alice": "age1aaa", "eve": "age1eve"}

	mac1 := computeMAC(dataKey, 1,"dk", recipients1, secrets)
	mac2 := computeMAC(dataKey, 1,"dk", recipients2, secrets)
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_DetectsVersionTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}

	mac1 := computeMAC(dataKey, 1, "dk", recipients, secrets)
	mac2 := computeMAC(dataKey, 99, "dk", recipients, secrets)
	assert.NotEqual(t, mac1, mac2)
}

func TestComputeMAC_DetectsDataKeyTampering(t *testing.T) {
	dataKey, _ := generateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}

	mac1 := computeMAC(dataKey, 1,"dk1", recipients, secrets)
	mac2 := computeMAC(dataKey, 1,"dk2", recipients, secrets)
	assert.NotEqual(t, mac1, mac2)
}

// --- File format tests ---

func TestMarshalLoadRoundtrip(t *testing.T) {
	useTempDir(t)

	ef := &EncryptedFile{
		Version:    1,
		MAC:        "deadbeef",
		DataKey:    "base64data",
		Recipients: map[string]string{"alice": "age1abc", "bob": "age1def"},
		Secrets:    map[string]string{"SECRET": "enc1", "API_KEY": "enc2"},
	}

	err := saveEncryptedFile(".env.enc", ef)
	require.NoError(t, err)

	loaded, err := loadEncryptedFile(".env.enc")
	require.NoError(t, err)

	assert.Equal(t, ef.Version, loaded.Version)
	assert.Equal(t, ef.MAC, loaded.MAC)
	assert.Equal(t, ef.DataKey, loaded.DataKey)
	assert.Equal(t, ef.Recipients, loaded.Recipients)
	assert.Equal(t, ef.Secrets, loaded.Secrets)
}

func TestSaveEncryptedFile_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions not supported on Windows")
	}
	useTempDir(t)

	ef := &EncryptedFile{
		Version:    1,
		MAC:        "test",
		DataKey:    "test",
		Recipients: map[string]string{},
		Secrets:    map[string]string{},
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
		Version:    1,
		MAC:        "test",
		DataKey:    "test",
		Recipients: map[string]string{},
		Secrets:    map[string]string{},
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
		Version:    1,
		MAC:        "mac",
		DataKey:    "dk",
		Recipients: map[string]string{"bob": "age1bbb", "alice": "age1aaa"},
		Secrets:    map[string]string{"ZZZ": "enc1", "AAA": "enc2"},
	}

	data, err := marshalEncryptedFile(ef)
	require.NoError(t, err)
	out := string(data)

	// Recipients should be sorted
	aliceIdx := strings.Index(out, "alice")
	bobIdx := strings.Index(out, "bob")
	assert.Greater(t, bobIdx, aliceIdx, "alice should come before bob")

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
	assert.Contains(t, string(data), "version = 1")

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

	// Capture the old wrapped data key
	oldDataKey := ef.DataKey

	// Remove user2 (simulating usersRemoveCmd logic: decrypt then re-encrypt)
	loaded, _ := loadEncryptedFile(".env.enc")
	decrypted, err := decryptSecrets(loaded)
	require.NoError(t, err)
	newRecipients := map[string]string{"user1": pub1}
	newEf, err := encryptSecrets(decrypted, newRecipients)
	require.NoError(t, err)
	require.NoError(t, saveEncryptedFile(".env.enc", newEf))

	// Data key should be different (rotated)
	assert.NotEqual(t, oldDataKey, newEf.DataKey)

	// Old data key should not decrypt new secrets
	oldDK, err := unwrapDataKey(oldDataKey, priv1)
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

func TestFindEncFile_WalksUp(t *testing.T) {
	dir := t.TempDir()
	// Resolve symlinks (macOS /var -> /private/var) to match os.Getwd()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	// Create .env.enc in root
	ef := &EncryptedFile{
		Version:    1,
		MAC:        "test",
		DataKey:    "test",
		Recipients: map[string]string{},
		Secrets:    map[string]string{},
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
		mac1 := computeMAC(dataKey, 1,"dk", recipients, secrets)
		mac2 := computeMAC(dataKey, 1,"dk", recipients, secrets)
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

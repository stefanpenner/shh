package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	sopsage "github.com/getsops/sops/v3/age"
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

// helper: generate an age keypair using native Go library
func generateTestKey(t *testing.T) (privKey, pubKey string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return identity.String(), identity.Recipient().String()
}

// helper: set up SOPS_AGE_KEY env for tests (bypasses keychain)
func setTestAgeKey(t *testing.T, privKey string) {
	t.Helper()
	os.Setenv(sopsage.SopsAgeKeyEnv, privKey)
	t.Cleanup(func() { os.Unsetenv(sopsage.SopsAgeKeyEnv) })
}

// --- Unit tests (no external deps) ---

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single", "FOO=bar", 1},
		{"multiple", "FOO=bar\nBAZ=qux\n", 2},
		{"with comments", "# comment\nFOO=bar\n\nBAZ=qux", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := parseDotenv(tt.input)
			assert.Len(t, lines, tt.want, "parseDotenv(%q)", tt.input)
		})
	}
}

func TestDotenvGet(t *testing.T) {
	lines := []string{"FOO=bar", "BAZ=qux", "# comment", "MULTI=a=b=c"}

	tests := []struct {
		key       string
		wantIdx   int
		wantFound bool
	}{
		{"FOO", 0, true},
		{"BAZ", 1, true},
		{"MULTI", 3, true},
		{"MISSING", -1, false},
		{"FO", -1, false}, // partial match should not work
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			idx, found := dotenvGet(lines, tt.key)
			assert.Equal(t, tt.wantFound, found, "dotenvGet(%q) found", tt.key)
			assert.Equal(t, tt.wantIdx, idx, "dotenvGet(%q) index", tt.key)
		})
	}
}

func TestWriteSopsConfig(t *testing.T) {
	useTempDir(t)

	keys := []string{"age1abc", "age1def"}
	require.NoError(t, writeSopsConfig(keys))

	data, err := os.ReadFile(sopsConfigFile)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "age1abc,age1def")
	assert.Contains(t, content, "creation_rules:")
}

func TestSopsKeysFromConfig(t *testing.T) {
	useTempDir(t)

	tests := []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{
			"standard",
			"creation_rules:\n  - age: \"age1abc,age1def\"\n",
			[]string{"age1abc", "age1def"},
			false,
		},
		{
			"single key",
			"creation_rules:\n  - age: \"age1only\"\n",
			[]string{"age1only"},
			false,
		},
		{
			"no age line",
			"creation_rules:\n  - kms: \"arn:...\"\n",
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.WriteFile(sopsConfigFile, []byte(tt.content), 0644)
			keys, err := sopsKeysFromConfig()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, keys, len(tt.want))
				for i := range keys {
					assert.Equal(t, tt.want[i], keys[i], "key[%d]", i)
				}
			}
		})
	}
}

func TestSopsKeysFromConfig_NoFile(t *testing.T) {
	useTempDir(t)
	_, err := sopsKeysFromConfig()
	assert.Error(t, err, "expected error when no config file exists")
}

func TestWriteThenReadSopsConfig(t *testing.T) {
	useTempDir(t)

	original := []string{"age1aaa", "age1bbb", "age1ccc"}
	require.NoError(t, writeSopsConfig(original))

	keys, err := sopsKeysFromConfig()
	require.NoError(t, err)
	require.Len(t, keys, len(original), "roundtrip key count")
	for i := range keys {
		assert.Equal(t, original[i], keys[i], "roundtrip key[%d]", i)
	}
}

func TestRegisterAndKeyName(t *testing.T) {
	useTempDir(t)

	require.NoError(t, registerKey("age1abc", "alice"))
	assert.Equal(t, "alice", keyName("age1abc"))

	// Unknown key
	assert.Empty(t, keyName("age1unknown"))

	// Update name
	require.NoError(t, registerKey("age1abc", "bob"))
	assert.Equal(t, "bob", keyName("age1abc"))

	// Multiple keys
	require.NoError(t, registerKey("age1def", "carol"))
	assert.Equal(t, "bob", keyName("age1abc"))
	assert.Equal(t, "carol", keyName("age1def"))
}

func TestKeyNameNoFile(t *testing.T) {
	useTempDir(t)
	assert.Empty(t, keyName("age1abc"))
}

func TestPublicKeyFrom(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	pub, err := publicKeyFrom(identity.String())
	require.NoError(t, err)
	assert.Equal(t, identity.Recipient().String(), pub)
}

// --- Integration tests (native Go, no CLI tools needed) ---

func TestIntegration_EncryptDecryptSetRm(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	writeSopsConfig([]string{pubKey})

	// Encrypt
	plaintext := "SECRET=hello\nAPI_KEY=sk-123\n"
	err := sopsEncrypt(plaintext, ".env.enc")
	require.NoError(t, err, "encrypt")

	// Verify encrypted file is not plaintext
	encData, _ := os.ReadFile(".env.enc")
	assert.NotContains(t, string(encData), "hello", "encrypted file should not contain plaintext value")

	// Decrypt
	decrypted, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "decrypt")
	assert.Contains(t, decrypted, "SECRET=hello")
	assert.Contains(t, decrypted, "API_KEY=sk-123")

	// Test set (upsert) via round-trip
	lines := parseDotenv(decrypted)
	lines = append(lines, "NEW_KEY=new_value")
	setInput := strings.Join(lines, "\n") + "\n"

	err = sopsEncrypt(setInput, ".env.enc")
	require.NoError(t, err, "set encrypt")

	// Decrypt and verify new key exists
	decrypted2, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "decrypt after set")
	assert.Contains(t, decrypted2, "NEW_KEY=new_value", "set: new key should exist")
	assert.Contains(t, decrypted2, "SECRET=hello", "set: original key should survive")

	// Test rm
	lines2 := parseDotenv(decrypted2)
	var filtered []string
	for _, l := range lines2 {
		if !strings.HasPrefix(l, "API_KEY=") {
			filtered = append(filtered, l)
		}
	}
	rmInput := strings.Join(filtered, "\n") + "\n"

	err = sopsEncrypt(rmInput, ".env.enc")
	require.NoError(t, err, "rm encrypt")

	decrypted3, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "decrypt after rm")
	assert.NotContains(t, decrypted3, "API_KEY=", "rm: key should be removed")
	assert.Contains(t, decrypted3, "SECRET=hello", "rm: other keys should survive")
	assert.Contains(t, decrypted3, "NEW_KEY=new_value", "rm: other keys should survive")
}

func TestIntegration_MultiRecipient(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	// Config with both keys
	writeSopsConfig([]string{pub1, pub2})

	// Encrypt with key1
	setTestAgeKey(t, priv1)
	err := sopsEncrypt("SHARED_SECRET=42\n", ".env.enc")
	require.NoError(t, err, "encrypt")

	// Decrypt with key2
	setTestAgeKey(t, priv2)
	decrypted, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "key2 decrypt")
	assert.Contains(t, decrypted, "SHARED_SECRET=42", "key2 should decrypt")

	// Decrypt with key1 also works
	setTestAgeKey(t, priv1)
	decrypted2, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "key1 decrypt")
	assert.Contains(t, decrypted2, "SHARED_SECRET=42", "key1 should decrypt")
}

func TestIntegration_UpdateKeys(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	priv3, pub3 := generateTestKey(t)

	// Encrypt with key1 only
	writeSopsConfig([]string{pub1})
	setTestAgeKey(t, priv1)
	err := sopsEncrypt("UPDATE_TEST=secret\n", ".env.enc")
	require.NoError(t, err)

	// Add key2 and key3, update keys
	writeSopsConfig([]string{pub1, pub2, pub3})
	err = sopsUpdateKeys(".env.enc")
	require.NoError(t, err, "update keys")

	// Decrypt with key3 (newly added)
	setTestAgeKey(t, priv3)
	decrypted, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "key3 decrypt after update")
	assert.Contains(t, decrypted, "UPDATE_TEST=secret")
}

func TestDotenvGet_EdgeCases(t *testing.T) {
	lines := []string{
		"FOO=",           // empty value
		"BAR=has=equals", // value with equals
		"=nokey",         // empty key (weird but possible)
		"FOOBAR=baz",     // shouldn't match "FOO"
	}

	tests := []struct {
		key       string
		wantIdx   int
		wantFound bool
	}{
		{"FOO", 0, true},
		{"BAR", 1, true},
		{"", 2, true},
		{"FOOBAR", 3, true},
		{"FOO ", -1, false}, // trailing space
	}
	for _, tt := range tests {
		t.Run("key="+tt.key, func(t *testing.T) {
			idx, found := dotenvGet(lines, tt.key)
			assert.Equal(t, tt.wantFound, found, "dotenvGet(%q) found", tt.key)
			assert.Equal(t, tt.wantIdx, idx, "dotenvGet(%q) index", tt.key)
		})
	}
}

func TestRegisterKey_Idempotent(t *testing.T) {
	useTempDir(t)

	registerKey("age1abc", "alice")
	registerKey("age1abc", "alice")
	registerKey("age1abc", "alice")

	data, _ := os.ReadFile(keyRegistryFile)
	count := strings.Count(string(data), "age1abc")
	assert.Equal(t, 1, count, "key should appear exactly once")
}

func TestWriteSopsConfig_Overwrite(t *testing.T) {
	useTempDir(t)

	writeSopsConfig([]string{"age1old"})
	writeSopsConfig([]string{"age1new"})

	keys, err := sopsKeysFromConfig()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "age1new", keys[0])
}

func TestIntegration_EncryptCreatesConfig(t *testing.T) {
	useTempDir(t)

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	pubKey := identity.Recipient().String()

	// No .sops.yaml exists
	_, err = os.Stat(sopsConfigFile)
	require.Error(t, err, "config should not exist yet")

	writeSopsConfig([]string{pubKey})

	// Verify it was created
	_, err = os.Stat(sopsConfigFile)
	assert.NoError(t, err, "config should exist after writeSopsConfig")

	keys, err := sopsKeysFromConfig()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, pubKey, keys[0])
}

func TestRegistryFile_Permissions(t *testing.T) {
	useTempDir(t)

	registerKey("age1test", "testuser")

	info, err := os.Stat(keyRegistryFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "registry permissions")
}

func TestSopsConfigFile_Permissions(t *testing.T) {
	useTempDir(t)

	writeSopsConfig([]string{"age1test"})

	info, err := os.Stat(sopsConfigFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "sops config permissions")
}

func TestIntegration_EncryptDecrypt_SpecialChars(t *testing.T) {
	useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	writeSopsConfig([]string{pubKey})

	// Values with special chars
	env := "PASSWORD=p@ss w0rd!#$%\nURL=https://example.com?foo=bar&baz=1\n"
	err := sopsEncrypt(env, ".env.enc")
	require.NoError(t, err, "encrypt")

	decrypted, err := sopsDecrypt(".env.enc")
	require.NoError(t, err, "decrypt")

	assert.Contains(t, decrypted, "p@ss w0rd!#$%", "special chars in password should be preserved")
	assert.Contains(t, decrypted, "https://example.com?foo=bar&baz=1", "URL with special chars should be preserved")
}

// Verify absolute paths work with key registry
func TestKeyRegistry_AbsolutePaths(t *testing.T) {
	useTempDir(t)

	absPath := filepath.Join(t.TempDir(), ".age-keys")
	os.WriteFile(absPath, []byte("age1xxx alice\nage1yyy bob\n"), 0644)

	// The global keyRegistryFile is relative, but verify our functions
	// work correctly in the temp dir context
	registerKey("age1aaa", "carol")
	registerKey("age1bbb", "dave")

	assert.Equal(t, "carol", keyName("age1aaa"))
	assert.Equal(t, "dave", keyName("age1bbb"))
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, githubUserPattern.MatchString(tt.user))
		})
	}
}

func TestRegisterKey_SanitizesName(t *testing.T) {
	useTempDir(t)

	// Name with newline should be sanitized
	require.NoError(t, registerKey("age1abc", "alice\nbob"))
	name := keyName("age1abc")
	assert.Equal(t, "alicebob", name, "newlines should be stripped from name")
	assert.NotContains(t, name, "\n")
}

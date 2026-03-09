package encfile

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

func generateTestKey(t *testing.T) (privKey, pubKey string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return identity.String(), identity.Recipient().String()
}

func setTestAgeKey(t *testing.T, privKey string) {
	t.Helper()
	os.Setenv("SHH_AGE_KEY", privKey)
	t.Cleanup(func() { os.Unsetenv("SHH_AGE_KEY") })
}

func TestMarshalLoadRoundtrip(t *testing.T) {
	useTempDir(t)

	ef := &EncryptedFile{
		Version:     2,
		MAC:         "deadbeef",
		Recipients:  map[string]string{"alice": "age1abc", "bob": "age1def"},
		WrappedKeys: map[string]string{"alice": "wk1", "bob": "wk2"},
		Secrets:     map[string]string{"SECRET": "enc1", "API_KEY": "enc2"},
	}

	err := Save(".env.enc", ef)
	require.NoError(t, err)

	loaded, err := Load(".env.enc")
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

	err := Save(".env.enc", ef)
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

	err := Save(".env.enc", ef)
	require.NoError(t, err)

	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".shh-"), "temp file should be cleaned up: %s", e.Name())
	}
}

func TestLoadEncryptedFile_InvalidVersion(t *testing.T) {
	useTempDir(t)

	os.WriteFile(".env.enc", []byte("version = 99\nmac = \"x\"\ndata_key = \"x\"\n"), 0600)
	_, err := Load(".env.enc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported file version")
}

func TestLoadEncryptedFile_EmptySecrets(t *testing.T) {
	useTempDir(t)

	content := "version = 1\nmac = \"x\"\ndata_key = \"x\"\n\n[recipients]\nalice = \"age1abc\"\n\n[secrets]\n"
	os.WriteFile(".env.enc", []byte(content), 0600)

	ef, err := Load(".env.enc")
	require.NoError(t, err)
	assert.Empty(t, ef.Secrets)
	assert.Len(t, ef.Recipients, 1)
}

func TestLoadFromBytes(t *testing.T) {
	data := []byte("version = 2\nmac = \"test\"\n\n[recipients]\nalice = \"age1abc\"\n\n[wrapped_keys]\nalice = \"wk1\"\n\n[secrets]\nSECRET = \"enc1\"\n")
	ef, err := LoadFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 2, ef.Version)
	assert.Equal(t, "test", ef.MAC)
	assert.Equal(t, "age1abc", ef.Recipients["alice"])
	assert.Equal(t, "enc1", ef.Secrets["SECRET"])
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

	data, err := Marshal(ef)
	require.NoError(t, err)
	out := string(data)

	aliceIdx := strings.Index(out, "alice")
	bobIdx := strings.Index(out, "bob")
	assert.Greater(t, bobIdx, aliceIdx, "alice should come before bob")

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

func FuzzTomlKey(f *testing.F) {
	f.Add("SIMPLE")
	f.Add("has space")
	f.Add("")
	f.Add("with.dot")
	f.Fuzz(func(t *testing.T, input string) {
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

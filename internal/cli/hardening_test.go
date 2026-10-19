package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

func TestSecretValueRefusesArgByDefault(t *testing.T) {
	_, err := secretValue("hunter2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shh set KEY -")
	assert.NotContains(t, err.Error(), "hunter2")

	v, err := secretValue("hunter2", true)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", v)
}

func TestSetCmdRefusesArgWithoutAllowArg(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"set", "FOO", "bar"})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--allow-arg")
}

func TestCheckPassphraseStrength(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"repeated char", "aaaaaaaaaaaaaaaa", false},
		{"digits only low diversity", "1212121212121212", false},
		{"single class many distinct", "abcdefghijklmnop", false},
		{"diceware words", "correct horse battery staple", true},
		{"mixed", "Tr0ub4dor-and-3", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPassphraseStrength(tt.in)
			if tt.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestScrubAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".shh-edit-x.env")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("SECRET"), 2000), 0600))
	f, err := os.Open(path) // keep an fd to observe contents after unlink
	require.NoError(t, err)
	defer f.Close()

	scrubAndRemove(path)

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
	data := make([]byte, 12000)
	n, _ := f.Read(data)
	assert.Equal(t, 12000, n)
	assert.Equal(t, make([]byte, 12000), data, "contents must be zeroed before unlink")
	scrubAndRemove(path) // missing file is fine
}

func TestConfirmGitHubKey(t *testing.T) {
	orig := confirmPrompt
	defer func() { confirmPrompt = orig }()

	asked := false
	confirmPrompt = func(string) (bool, error) { asked = true; return false, nil }
	err := confirmGitHubKey("alice", "age1xyz", "SHA256:abc", false)
	require.Error(t, err, "no confirmation must not add")
	assert.True(t, asked)

	confirmPrompt = func(string) (bool, error) { return true, nil }
	require.NoError(t, confirmGitHubKey("alice", "age1xyz", "SHA256:abc", false))

	confirmPrompt = func(string) (bool, error) { return false, errors.New("eof") }
	require.Error(t, confirmGitHubKey("alice", "age1xyz", "SHA256:abc", false))

	confirmPrompt = func(string) (bool, error) { t.Fatal("must not prompt with --confirm"); return false, nil }
	require.NoError(t, confirmGitHubKey("alice", "age1xyz", "SHA256:abc", true))
}

func TestDoctorMACAndExtractableWarning(t *testing.T) {
	dir := useTempDir(t)
	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	ef, err := encfile.EncryptSecrets(map[string]string{"A": "1"}, map[string]string{"https://github.com/alice": pub})
	require.NoError(t, err)
	encFile := filepath.Join(dir, ".env.enc")
	require.NoError(t, encfile.Save(encFile, ef))

	run := func() []DoctorCheck {
		return RunDoctorChecks(
			func() (string, error) { return priv, nil },
			func() string { return "alice" },
			func() []string { return []string{"k"} },
			encFile,
		)
	}
	byName := func(cs []DoctorCheck, n string) *DoctorCheck {
		for i := range cs {
			if cs[i].Name == n {
				return &cs[i]
			}
		}
		return nil
	}
	checks := run()
	require.NotNil(t, byName(checks, "mac"))
	assert.True(t, byName(checks, "mac").Status)
	w := byName(checks, "extractable keys")
	require.NotNil(t, w)
	assert.Contains(t, w.Message, "rotate")

	// Tamper with a secret value: MAC must fail.
	loaded, err := encfile.Load(encFile)
	require.NoError(t, err)
	loaded.MAC = "deadbeef"
	require.NoError(t, encfile.Save(encFile, loaded))
	m := byName(run(), "mac")
	require.NotNil(t, m)
	assert.False(t, m.Status)
}

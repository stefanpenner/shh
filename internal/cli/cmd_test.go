package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
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

func setupEncryptedFile(t *testing.T, file string, secrets map[string]string, pubKey string) {
	t.Helper()
	recipients := map[string]string{"test-user": pubKey}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	err = encfile.Save(file, ef)
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

func TestCmdRun_FiltersShhPlaintext(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"FOO": "bar"}, pubKey)

	t.Setenv("SHH_PLAINTEXT", "/tmp/some-plaintext.env")
	err := cmdRun(".env.enc", []string{"printenv", "SHH_PLAINTEXT"})
	assert.Error(t, err, "SHH_PLAINTEXT should not be in child environment")
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
		{"no args", nil, "", nil},
		{"command only, no separator", []string{"echo", "hello"}, "", []string{"echo", "hello"}},
		{"separator with command", []string{"--", "echo", "hello"}, "", []string{"echo", "hello"}},
		{"file and separator", []string{"secrets.enc", "--", "echo", "hello"}, "secrets.enc", []string{"echo", "hello"}},
		{"separator only", []string{"--"}, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, cmd := parseRunArgs(tt.args)
			assert.Equal(t, tt.wantFile, file)
			assert.Equal(t, tt.wantCmd, cmd)
		})
	}
}

// --- Env command tests ---

func TestCmdEnv_WarnsWhenNotTTY(t *testing.T) {
	useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	ef, err := encfile.EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

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
	ef, err := encfile.EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

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
	ef, err := encfile.EncryptSecrets(secrets, map[string]string{"testuser": pubKey})
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	var stderr2 bytes.Buffer
	err = cmdEnv(".env.enc", &stderr2, func() bool { return false }, true)
	require.NoError(t, err)
	assert.Empty(t, stderr2.String())
}

// --- Template command tests ---

func TestCmdTemplate(t *testing.T) {
	dir := useTempDir(t)
	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)
	setupEncryptedFile(t, ".env.enc", map[string]string{"API_KEY": "my-key", "DB_PASS": "secret"}, pubKey)

	tplPath := filepath.Join(dir, "config.tpl")
	require.NoError(t, os.WriteFile(tplPath, []byte("api={{API_KEY}} db={{DB_PASS}}"), 0600))

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

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Write([]byte("token={{TOKEN}}"))
	w.Close()
	os.Stdin = r

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	err := cmdTemplate("-", ".env.enc")
	wOut.Close()
	os.Stdout = oldStdout
	os.Stdin = oldStdin

	require.NoError(t, err)
	var buf bytes.Buffer
	io.Copy(&buf, rOut)
	assert.Equal(t, "token=tok123", buf.String())
}

// --- Merge command tests ---

func TestCmdMerge(t *testing.T) {
	useTempDir(t)

	priv, pub := generateTestKey(t)
	setTestAgeKey(t, priv)
	recipients := map[string]string{"testuser": pub}

	ancestor, err := encfile.EncryptSecrets(map[string]string{"BASE": "value"}, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save("ancestor.enc", ancestor))

	oursSecrets := map[string]string{"BASE": "value", "OURS_KEY": "ours_val"}
	oursEf, err := encfile.EncryptSecrets(oursSecrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save("ours.enc", oursEf))

	theirsSecrets := map[string]string{"BASE": "value", "THEIRS_KEY": "theirs_val"}
	theirsEf, err := encfile.EncryptSecrets(theirsSecrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save("theirs.enc", theirsEf))

	err = cmdMerge("ancestor.enc", "ours.enc", "theirs.enc")
	require.NoError(t, err)

	merged, err := encfile.Load("ours.enc")
	require.NoError(t, err)
	decrypted, err := encfile.DecryptSecrets(merged, priv)
	require.NoError(t, err)

	assert.Equal(t, "value", decrypted["BASE"])
	assert.Equal(t, "ours_val", decrypted["OURS_KEY"])
	assert.Equal(t, "theirs_val", decrypted["THEIRS_KEY"])
}

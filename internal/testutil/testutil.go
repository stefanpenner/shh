package testutil

import (
	"os"
	"os/exec"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

// UseTempDir changes to a temp dir and restores the original on cleanup.
func UseTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)                         // #nosec G104 -- test helper; chdir failure surfaces as test assertion errors
	t.Cleanup(func() { os.Chdir(orig) }) // #nosec G104 -- best-effort restore in test cleanup
	return dir
}

// GenerateTestKey generates an age keypair for testing.
func GenerateTestKey(t *testing.T) (privKey, pubKey string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return identity.String(), identity.Recipient().String()
}

// SetTestAgeKey sets SHH_AGE_KEY for tests (bypasses keyring).
func SetTestAgeKey(t *testing.T, privKey string) {
	t.Helper()
	os.Setenv("SHH_AGE_KEY", privKey) // #nosec G104 -- test helper; failure caught by test assertions
	t.Cleanup(func() { os.Unsetenv("SHH_AGE_KEY") })
}

// SetupEncryptedFile creates an encrypted file for testing.
func SetupEncryptedFile(t *testing.T, file string, secrets map[string]string, pubKey string) {
	t.Helper()
	recipients := map[string]string{"test-user": pubKey}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	err = encfile.Save(file, ef)
	require.NoError(t, err)
}

// GitRun runs a git command in dir and fails the test on error.
func GitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- test helper; args are test-controlled, not user input
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

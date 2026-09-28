package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/vaultadmit"
)

func TestCmdSet_RefusesUnreviewedRecipients(t *testing.T) {
	dir := useTempDir(t)
	victimPriv, victimPub := generateTestKey(t)
	attackerPriv, attackerPub := generateTestKey(t)
	setTestAgeKey(t, victimPriv)

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=commit.gpgsign",
			"GIT_CONFIG_VALUE_0=false",
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	git("init", "-b", "main")
	honest, err := encfile.EncryptSecrets(
		map[string]string{"API": "real"},
		map[string]string{"alice": victimPub},
	)
	require.NoError(t, err)
	path := filepath.Join(dir, ".env.enc")
	require.NoError(t, encfile.Save(path, honest))
	git("add", ".env.enc")
	git("commit", "-m", "base")

	forged, err := encfile.EncryptSecrets(
		map[string]string{"API": "evil"},
		map[string]string{"alice": victimPub, "eve": attackerPub},
	)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(path, forged))
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	err = cmdSet(path, "NEW", "fresh", false)
	require.ErrorIs(t, err, vaultadmit.ErrUnreviewed)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)

	require.NoError(t, cmdSet(path, "NEW", "fresh", true))
	loaded, err := encfile.Load(path)
	require.NoError(t, err)
	opened, err := encfile.DecryptSecrets(loaded, attackerPriv)
	require.NoError(t, err)
	require.Equal(t, "fresh", opened["NEW"])
}

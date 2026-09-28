package encfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/recipientmerge"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=commit.gpgsign",
		"GIT_CONFIG_VALUE_0=false",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

func TestAutoResolve_OnLoad(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	priv, pub := generateTestKey(t)
	recipients := map[string]string{"testuser": pub}

	gitRun(t, dir, "init", "-b", "main")
	os.Chdir(dir)

	baseEf, err := EncryptSecrets(map[string]string{"BASE": "value"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), baseEf))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "base")

	gitRun(t, dir, "checkout", "-b", "branch-a")
	efA, err := EncryptSecrets(map[string]string{"BASE": "value", "KEY_A": "a_val"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), efA))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "add KEY_A")

	gitRun(t, dir, "checkout", "main")
	gitRun(t, dir, "checkout", "-b", "branch-b")
	efB, err := EncryptSecrets(map[string]string{"BASE": "value", "KEY_B": "b_val"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), efB))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "add KEY_B")

	mergeCmd := exec.Command("git", "merge", "branch-a")
	mergeCmd.Dir = dir
	mergeCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	mergeCmd.Run() // expected to fail

	lsOut, _ := exec.Command("git", "ls-files", "-u", ".env.enc").Output()
	require.NotEmpty(t, lsOut, "file should be in conflicted state")

	// TryAutoResolve should resolve
	ef, err := TryAutoResolve(filepath.Join(dir, ".env.enc"), priv)
	require.NoError(t, err)

	decrypted, err := DecryptSecrets(ef, priv)
	require.NoError(t, err)
	assert.Equal(t, "value", decrypted["BASE"])
	assert.Equal(t, "a_val", decrypted["KEY_A"])
	assert.Equal(t, "b_val", decrypted["KEY_B"])

	lsOut, _ = exec.Command("git", "ls-files", "-u", ".env.enc").Output()
	assert.Empty(t, lsOut, "file should no longer be conflicted")
}

func TestAutoResolve_Conflict_Fails(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	priv, pub := generateTestKey(t)
	recipients := map[string]string{"testuser": pub}

	gitRun(t, dir, "init", "-b", "main")
	os.Chdir(dir)

	baseEf, err := EncryptSecrets(map[string]string{"SECRET": "original"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), baseEf))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "base")

	gitRun(t, dir, "checkout", "-b", "branch-a")
	efA, err := EncryptSecrets(map[string]string{"SECRET": "from_a"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), efA))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "change SECRET in a")

	gitRun(t, dir, "checkout", "main")
	gitRun(t, dir, "checkout", "-b", "branch-b")
	efB, err := EncryptSecrets(map[string]string{"SECRET": "from_b"}, recipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), efB))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "change SECRET in b")

	mergeCmd := exec.Command("git", "merge", "branch-a")
	mergeCmd.Dir = dir
	mergeCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	mergeCmd.Run()

	_, err = TryAutoResolve(filepath.Join(dir, ".env.enc"), priv)
	assert.Error(t, err)
}

func TestAutoResolve_RefusesRecipientChange(t *testing.T) {
	dir := t.TempDir()
	alicePriv, alicePub := generateTestKey(t)
	_, recoveryPub := generateTestKey(t)
	evePriv, evePub := generateTestKey(t)

	baseRecipients := map[string]string{"alice": alicePub, "recovery": recoveryPub}
	gitRun(t, dir, "init", "-b", "main")

	base, err := EncryptSecrets(map[string]string{"BASE": "keep"}, baseRecipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), base))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "base")

	gitRun(t, dir, "checkout", "-b", "ours")
	ours, err := EncryptSecrets(map[string]string{"BASE": "keep", "LOCAL": "secret"}, baseRecipients)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), ours))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "local")

	gitRun(t, dir, "checkout", "main")
	gitRun(t, dir, "checkout", "-b", "theirs")
	theirs, err := EncryptSecrets(
		map[string]string{"BASE": "nope"},
		map[string]string{"alice": alicePub, "eve": evePub},
	)
	require.NoError(t, err)
	require.NoError(t, Save(filepath.Join(dir, ".env.enc"), theirs))
	gitRun(t, dir, "add", ".env.enc")
	gitRun(t, dir, "commit", "-m", "forged")

	gitRun(t, dir, "checkout", "ours")
	merge := exec.Command("git", "merge", "theirs")
	merge.Dir = dir
	merge.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=commit.gpgsign",
		"GIT_CONFIG_VALUE_0=false",
	)
	out, err := merge.CombinedOutput()
	require.Error(t, err, "expected a conflict: %s", out)

	_, err = TryAutoResolve(filepath.Join(dir, ".env.enc"), alicePriv)
	require.ErrorIs(t, err, recipientmerge.ErrSetsDiffer)

	unmerged, err := exec.Command("git", "-C", dir, "ls-files", "-u", "--", ".env.enc").Output()
	require.NoError(t, err)
	require.NotEmpty(t, unmerged)

	_, err = Load(filepath.Join(dir, ".env.enc"))
	require.Error(t, err, "the work tree must stay conflicted")

	stage, err := exec.Command("git", "-C", dir, "show", ":2:.env.enc").Output()
	require.NoError(t, err)
	oursFile, err := LoadFromBytes(stage)
	require.NoError(t, err)
	_, err = DecryptSecrets(oursFile, evePriv)
	require.Error(t, err, "eve must not open the local side")
}

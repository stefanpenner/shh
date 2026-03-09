package cli

import (
	"path/filepath"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

func TestRunDoctorChecks_AllPass(t *testing.T) {
	dir := useTempDir(t)

	privKey, pubKey := generateTestKey(t)
	setTestAgeKey(t, privKey)

	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pubKey}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	encFile := filepath.Join(dir, ".env.enc")
	require.NoError(t, encfile.Save(encFile, ef))

	checks := RunDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		encFile,
	)

	require.Len(t, checks, 5)
	assert.True(t, checks[0].Status, "age key check should pass")
	assert.Contains(t, checks[0].Message, "age1")
	assert.True(t, checks[1].Status, "github cli check should pass")
	assert.True(t, checks[2].Status, "ssh keys check should pass")
	assert.True(t, checks[3].Status, "encrypted file check should pass")
	assert.True(t, checks[4].Status, "recipient check should pass")
}

func TestRunDoctorChecks_NoKey(t *testing.T) {
	checks := RunDoctorChecks(
		func() (string, error) { return "", errors.New("no key") },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.False(t, checks[0].Status, "age key check should fail")
	assert.Contains(t, checks[0].Message, "no key found")
}

func TestRunDoctorChecks_NoGitHub(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := RunDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.True(t, checks[0].Status)
	assert.False(t, checks[1].Status, "github cli check should fail")
}

func TestRunDoctorChecks_NoSSHKeys(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := RunDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return nil },
		"/nonexistent/.env.enc",
	)

	assert.False(t, checks[2].Status, "ssh keys check should fail")
}

func TestRunDoctorChecks_NoEncFile(t *testing.T) {
	privKey, _ := generateTestKey(t)

	checks := RunDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		"/nonexistent/.env.enc",
	)

	assert.False(t, checks[3].Status, "encrypted file check should fail")
	assert.Len(t, checks, 4)
}

func TestRunDoctorChecks_NotInRecipients(t *testing.T) {
	dir := useTempDir(t)

	privKey, _ := generateTestKey(t)
	otherPriv, otherPub := generateTestKey(t)

	setTestAgeKey(t, otherPriv)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/bob": otherPub}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	encFile := filepath.Join(dir, ".env.enc")
	require.NoError(t, encfile.Save(encFile, ef))

	checks := RunDoctorChecks(
		func() (string, error) { return privKey, nil },
		func() string { return "alice" },
		func() []string { return []string{"/home/alice/.ssh/id_ed25519"} },
		encFile,
	)

	require.Len(t, checks, 5)
	assert.True(t, checks[3].Status, "encrypted file check should pass")
	assert.False(t, checks[4].Status, "recipient check should fail")
	assert.Contains(t, checks[4].Message, "NOT in the recipients list")
}

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

func TestUsersRemoveByGitHubUsername(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/rwjblue": pub2}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	err = usersRemoveCmd([]string{"rwjblue"})
	require.NoError(t, err)

	reloaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
	_, hasAlice := reloaded.Recipients["https://github.com/alice"]
	assert.True(t, hasAlice, "alice should remain")
}

func TestUsersRemoveByDisplayName(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/bob": pub2}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	err = usersRemoveCmd([]string{"https://github.com/bob"})
	require.NoError(t, err)

	reloaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
}

func TestUsersRemoveByNumber(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1, "https://github.com/bob": pub2}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Remove by number (bob is #2 alphabetically)
	err = usersRemoveCmd([]string{"2"})
	require.NoError(t, err)

	reloaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, reloaded.Recipients, 1)
	_, hasAlice := reloaded.Recipients["https://github.com/alice"]
	assert.True(t, hasAlice)
}

func TestUsersAddRemoveLifecycle(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	priv2, pub2 := generateTestKey(t)

	setTestAgeKey(t, priv1)
	secrets := map[string]string{"SECRET": "lifecycle-test"}
	recipients := map[string]string{
		"https://github.com/alice": pub1,
		"https://github.com/bob":   pub2,
	}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Both can decrypt
	setTestAgeKey(t, priv1)
	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err := encfile.DecryptSecrets(loaded, priv1)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	setTestAgeKey(t, priv2)
	loaded, err = encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err = encfile.DecryptSecrets(loaded, priv2)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	// Remove bob
	setTestAgeKey(t, priv1)
	err = usersRemoveCmd([]string{"bob"})
	require.NoError(t, err)

	// alice can still decrypt
	loaded, err = encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err = encfile.DecryptSecrets(loaded, priv1)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])

	// bob can no longer decrypt
	loaded, err = encfile.Load(".env.enc")
	require.NoError(t, err)
	_, err = encfile.DecryptSecrets(loaded, priv2)
	assert.Error(t, err)

	// Re-add bob
	setTestAgeKey(t, priv1)
	loaded, err = encfile.Load(".env.enc")
	require.NoError(t, err)
	newRecipients := make(map[string]string, len(loaded.Recipients)+1)
	for k, v := range loaded.Recipients {
		newRecipients[k] = v
	}
	newRecipients["https://github.com/bob"] = pub2
	err = encfile.ReWrapDataKey(loaded, newRecipients, priv1)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", loaded))

	// bob can decrypt again
	loaded, err = encfile.Load(".env.enc")
	require.NoError(t, err)
	dec, err = encfile.DecryptSecrets(loaded, priv2)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-test", dec["SECRET"])
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
		{"shh-user://production-deploy", "production-deploy"},
		{"shh-user://ci", "ci"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RecipientDisplayName(tt.name))
		})
	}
}

func TestUsersAddWithNameGeneratesKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	setTestAgeKey(t, priv1)

	// Create initial enc file with one recipient
	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Add a deploy key with --name (no --key, should generate)
	err = usersAddCmd(nil, "production-deploy", "")
	require.NoError(t, err)

	// Verify the recipient was added with shh-user:// prefix
	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, loaded.Recipients, 2)
	_, hasDeploy := loaded.Recipients["shh-user://production-deploy"]
	assert.True(t, hasDeploy, "should have shh-user://production-deploy recipient")

	// Verify original user can still decrypt
	dec, err := encfile.DecryptSecrets(loaded, priv1)
	require.NoError(t, err)
	assert.Equal(t, "hello", dec["SECRET"])
}

func TestUsersAddWithNameAndKey(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	setTestAgeKey(t, priv1)

	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{"https://github.com/alice": pub1}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Add with --name and --key
	err = usersAddCmd(nil, "staging-deploy", pub2)
	require.NoError(t, err)

	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, loaded.Recipients, 2)
	assert.Equal(t, pub2, loaded.Recipients["shh-user://staging-deploy"])
}

func TestUsersAddWithNameRequiresName(t *testing.T) {
	// No positional arg, no --name → error
	err := usersAddCmd(nil, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--name")
}

func TestUsersAddWithNameRejectsInvalidName(t *testing.T) {
	// Control characters in --name must be rejected before any file I/O.
	// Go's %q produces \a, \v etc. which are not valid TOML escape sequences,
	// which would corrupt the encrypted secrets file.
	invalidNames := []string{
		"deploy\x07prod",  // BEL — Go %q → \a, invalid in TOML
		"deploy\x0bprod",  // VT  — Go %q → \v, invalid in TOML
		"../traversal",    // path traversal
		"",                // empty string
		"has space",       // spaces not allowed
		"has/slash",       // slashes not allowed
	}
	for _, name := range invalidNames {
		err := usersAddCmd(nil, name, "")
		assert.Error(t, err, "expected error for deploy name %q", name)
	}
}

func TestUsersAddWithNameDuplicate(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	setTestAgeKey(t, priv1)

	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{
		"https://github.com/alice":      pub1,
		"shh-user://production-deploy": pub1,
	}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Adding the same name again should fail
	err = usersAddCmd(nil, "production-deploy", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already in use")
}

func TestUsersRemoveByDeployDisplayName(t *testing.T) {
	useTempDir(t)

	priv1, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)
	setTestAgeKey(t, priv1)

	secrets := map[string]string{"SECRET": "hello"}
	recipients := map[string]string{
		"https://github.com/alice":     pub1,
		"shh-user://production-deploy": pub2,
	}
	ef, err := encfile.EncryptSecrets(secrets, recipients)
	require.NoError(t, err)
	require.NoError(t, encfile.Save(".env.enc", ef))

	// Remove by display name (without shh-user:// prefix)
	err = usersRemoveCmd([]string{"production-deploy"})
	require.NoError(t, err)

	loaded, err := encfile.Load(".env.enc")
	require.NoError(t, err)
	assert.Len(t, loaded.Recipients, 1)
	_, hasAlice := loaded.Recipients["https://github.com/alice"]
	assert.True(t, hasAlice)
}

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RecipientDisplayName(tt.name))
		})
	}
}

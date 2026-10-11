package shhcore

import (
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

func TestOpenReadsOneSecret(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	ef, err := encfile.EncryptSecrets(
		map[string]string{"B_KEY": "beta", "A_KEY": "alpha"},
		map[string]string{"owner": identity.Recipient().String()},
	)
	require.NoError(t, err)
	raw, err := encfile.Marshal(ef)
	require.NoError(t, err)

	pub, err := PublicRecipient(identity.String())
	require.NoError(t, err)
	require.Equal(t, identity.Recipient().String(), pub)

	vault, err := Open(identity.String(), raw)
	require.NoError(t, err)
	require.Equal(t, pub, vault.Recipient())
	require.Equal(t, 2, vault.Count())

	first, err := vault.Name(0)
	require.NoError(t, err)
	second, err := vault.Name(1)
	require.NoError(t, err)
	require.Equal(t, "A_KEY", first)
	require.Equal(t, "B_KEY", second)

	got, err := vault.Secret("B_KEY")
	require.NoError(t, err)
	require.Equal(t, "beta", got)

	_, err = vault.Name(2)
	require.Error(t, err)

	vault.Close()
	_, err = vault.Secret("B_KEY")
	require.Error(t, err)
	vault.Close()
}

func TestOpenListsRecipients(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	ef, err := encfile.EncryptSecrets(
		map[string]string{"A_KEY": "alpha"},
		map[string]string{"zoe": other.Recipient().String(), "amy": identity.Recipient().String()},
	)
	require.NoError(t, err)
	raw, err := encfile.Marshal(ef)
	require.NoError(t, err)

	vault, err := Open(identity.String(), raw)
	require.NoError(t, err)
	require.Equal(t, 2, vault.RecipientCount())

	name, err := vault.RecipientName(0)
	require.NoError(t, err)
	key, err := vault.RecipientKey(0)
	require.NoError(t, err)
	require.Equal(t, "amy", name)
	require.Equal(t, identity.Recipient().String(), key)

	name, err = vault.RecipientName(1)
	require.NoError(t, err)
	require.Equal(t, "zoe", name)

	_, err = vault.RecipientName(2)
	require.Error(t, err)
	_, err = vault.RecipientKey(-1)
	require.Error(t, err)

	vault.Close()
	require.Equal(t, 0, vault.RecipientCount())
	_, err = vault.RecipientName(0)
	require.Error(t, err)
}

func TestSampleOpensSortedNames(t *testing.T) {
	sample, err := Sample()
	require.NoError(t, err)
	require.NotEmpty(t, sample.Identity)
	require.NotEmpty(t, sample.File)

	vault, err := Open(sample.Identity, sample.File)
	require.NoError(t, err)
	require.Equal(t, 2, vault.Count())
	first, err := vault.Name(0)
	require.NoError(t, err)
	second, err := vault.Name(1)
	require.NoError(t, err)
	require.Equal(t, "A_KEY", first)
	require.Equal(t, "B_KEY", second)

	alpha, err := vault.Secret("A_KEY")
	require.NoError(t, err)
	beta, err := vault.Secret("B_KEY")
	require.NoError(t, err)
	require.Equal(t, "alpha", alpha)
	require.Equal(t, "beta", beta)

	require.Equal(t, 2, vault.RecipientCount())
	var names []string
	for i := 0; i < vault.RecipientCount(); i++ {
		name, err := vault.RecipientName(i)
		require.NoError(t, err)
		names = append(names, name)
	}
	require.Equal(t, []string{
		"https://github.com/example",
		"https://github.com/octocat",
	}, names)

	ownerKey, err := vault.RecipientKey(0)
	require.NoError(t, err)
	require.Equal(t, vault.Recipient(), ownerKey)
}

func TestPublicRecipientRejectsEmpty(t *testing.T) {
	_, err := PublicRecipient("")
	require.Error(t, err)
	_, err = Open("", []byte("version = 2\n"))
	require.Error(t, err)
}

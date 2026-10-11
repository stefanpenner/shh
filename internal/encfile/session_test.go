package encfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSessionReadsOneSecret(t *testing.T) {
	priv, pub := generateTestKey(t)
	ef, err := EncryptSecrets(
		map[string]string{"B_KEY": "beta", "A_KEY": "alpha"},
		map[string]string{"owner": pub},
	)
	require.NoError(t, err)
	raw, err := Marshal(ef)
	require.NoError(t, err)

	session, err := Open(raw, priv)
	require.NoError(t, err)
	require.Equal(t, []string{"A_KEY", "B_KEY"}, session.Names())

	got, err := session.Secret("A_KEY")
	require.NoError(t, err)
	require.Equal(t, "alpha", got)

	_, err = session.Secret("MISSING")
	require.Error(t, err)

	session.Close()
	_, err = session.Secret("A_KEY")
	require.Error(t, err)
}

func TestSessionRejectsOtherIdentity(t *testing.T) {
	priv, pub := generateTestKey(t)
	other, _ := generateTestKey(t)
	ef, err := EncryptSecrets(
		map[string]string{"A_KEY": "alpha"},
		map[string]string{"owner": pub},
	)
	require.NoError(t, err)
	raw, err := Marshal(ef)
	require.NoError(t, err)

	_, err = Open(raw, other)
	require.Error(t, err)

	session, err := Open(raw, priv)
	require.NoError(t, err)
	session.Close()
}

func TestSessionListsRecipients(t *testing.T) {
	priv, pub := generateTestKey(t)
	_, otherPub := generateTestKey(t)
	ef, err := EncryptSecrets(
		map[string]string{"A_KEY": "alpha"},
		map[string]string{"zoe": otherPub, "amy": pub},
	)
	require.NoError(t, err)
	raw, err := Marshal(ef)
	require.NoError(t, err)

	session, err := Open(raw, priv)
	require.NoError(t, err)
	require.Equal(t, []Party{
		{Name: "amy", Key: pub},
		{Name: "zoe", Key: otherPub},
	}, session.Recipients())

	session.Close()
	require.Nil(t, session.Recipients())
}

func TestSessionRejectsTamper(t *testing.T) {
	priv, pub := generateTestKey(t)
	ef, err := EncryptSecrets(
		map[string]string{"A_KEY": "alpha"},
		map[string]string{"owner": pub},
	)
	require.NoError(t, err)
	raw, err := Marshal(ef)
	require.NoError(t, err)
	raw = bytes.Replace(raw, []byte("A_KEY"), []byte("C_KEY"), 1)

	_, err = Open(raw, priv)
	require.Error(t, err)
}

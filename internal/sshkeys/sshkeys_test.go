package sshkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func generatePassphraseProtectedTestKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func generateUnprotectedTestKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func setTestPassphraseReader(t *testing.T, passphrase string) {
	t.Helper()
	orig := ReadPassphrase
	ReadPassphrase = func(keyPath string) ([]byte, error) {
		return []byte(passphrase), nil
	}
	t.Cleanup(func() { ReadPassphrase = orig })
}

func TestToAge_UnprotectedKey(t *testing.T) {
	keyData := generateUnprotectedTestKey(t)
	priv, pub, err := ToAge(keyData, "/tmp/test_key")
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.True(t, strings.HasPrefix(*pub, "age1"))
}

func TestToAge_PassphraseProtected(t *testing.T) {
	passphrase := "test-passphrase-123"
	keyData := generatePassphraseProtectedTestKey(t, passphrase)
	setTestPassphraseReader(t, passphrase)

	priv, pub, err := ToAge(keyData, "/tmp/test_key")
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)
	assert.True(t, strings.HasPrefix(*pub, "age1"))
}

func TestToAge_WrongPassphrase(t *testing.T) {
	keyData := generatePassphraseProtectedTestKey(t, "correct-passphrase")
	setTestPassphraseReader(t, "wrong-passphrase")

	_, _, err := ToAge(keyData, "/tmp/test_key")
	assert.Error(t, err)
}

func TestToAge_PromptsWithCorrectPath(t *testing.T) {
	passphrase := "test-passphrase"
	keyData := generatePassphraseProtectedTestKey(t, passphrase)

	var capturedPath string
	orig := ReadPassphrase
	ReadPassphrase = func(keyPath string) ([]byte, error) {
		capturedPath = keyPath
		return []byte(passphrase), nil
	}
	t.Cleanup(func() { ReadPassphrase = orig })

	expectedPath := "/home/user/.ssh/id_ed25519"
	_, _, err := ToAge(keyData, expectedPath)
	require.NoError(t, err)
	assert.Equal(t, expectedPath, capturedPath)
}

func TestFindEd25519Keys_IncludesPassphraseProtected(t *testing.T) {
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	unprotectedData := generateUnprotectedTestKey(t)
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "id_ed25519"), unprotectedData, 0600))

	protectedData := generatePassphraseProtectedTestKey(t, "my-passphrase")
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "id_ed25519_protected"), protectedData, 0600))

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })

	keys := FindEd25519Keys()
	assert.Len(t, keys, 2, "should find both protected and unprotected keys")

	var foundUnprotected, foundProtected bool
	for _, k := range keys {
		if strings.HasSuffix(k, "id_ed25519") {
			foundUnprotected = true
		}
		if strings.HasSuffix(k, "id_ed25519_protected") {
			foundProtected = true
		}
	}
	assert.True(t, foundUnprotected, "should find unprotected key")
	assert.True(t, foundProtected, "should find passphrase-protected key")
}

func TestToAge_ProtectedAndUnprotectedProduceSameResult(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	passphrase := "test-pass"

	unprotectedBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	unprotectedPEM := pem.EncodeToMemory(unprotectedBlock)

	protectedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	protectedPEM := pem.EncodeToMemory(protectedBlock)

	_, pubUnprotected, err := ToAge(unprotectedPEM, "/tmp/key")
	require.NoError(t, err)

	setTestPassphraseReader(t, passphrase)
	_, pubProtected, err := ToAge(protectedPEM, "/tmp/key")
	require.NoError(t, err)

	assert.Equal(t, *pubUnprotected, *pubProtected, "same key should produce same age public key")
}

package envutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindEncFile_WalksUp(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	require.NoError(t, os.Chdir(dir))
	require.NoError(t, os.WriteFile(filepath.Join(dir, DefaultEncryptedFile), []byte("version = 2\nmac = \"x\"\n\n[recipients]\n\n[wrapped_keys]\n\n[secrets]\n"), 0600))

	nested := filepath.Join(dir, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.Chdir(nested))

	found := FindEncFile()
	assert.Equal(t, filepath.Join(dir, DefaultEncryptedFile), found)
}

func TestFindEncFile_FallsBack(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })

	require.NoError(t, os.Chdir(dir))
	found := FindEncFile()
	assert.Equal(t, DefaultEncryptedFile, found)
}

func TestEnvFlag(t *testing.T) {
	assert.Equal(t, "", EnvFlag(""))
	assert.Equal(t, "production.env.enc", EnvFlag("production"))
	assert.Equal(t, "staging.env.enc", EnvFlag("staging"))
}

func TestResolveFile(t *testing.T) {
	assert.Equal(t, "production.env.enc", ResolveFile("production", []string{"other.enc"}))
	assert.Equal(t, "other.enc", ResolveFile("", []string{"other.enc"}))
	result := ResolveFile("", nil)
	assert.NotEmpty(t, result)
}

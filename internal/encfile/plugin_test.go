package encfile_test

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

// buildStubPlugin compiles the shared test-only age plugin (defined under the
// crypto package's testdata) and prepends it to PATH, so the encrypt/decrypt
// path can be exercised through a real plugin subprocess.
func buildStubPlugin(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "age-plugin-shhtest")
	if runtime.GOOS == "windows" {
		bin += ".exe" // age resolves age-plugin-<name> via PATHEXT on Windows
	}
	out, err := exec.Command("go", "build", "-o", bin, "../crypto/testdata/age-plugin-shhtest").CombinedOutput()
	require.NoError(t, err, "build stub plugin: %s", out)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func stubKeys(t *testing.T) (recipient, identity string) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return plugin.EncodeRecipient("shhtest", key), plugin.EncodeIdentity("shhtest", key)
}

// TestDecryptSecretsWithPluginIdentity is the end-to-end proof that a plugin
// identity (YubiKey/Secure Enclave) can decrypt — exercising the trial-unwrap
// fallback in resolveDataKey, since a plugin recipient can't be derived from the
// identity to look the wrapped key up by name.
func TestDecryptSecretsWithPluginIdentity(t *testing.T) {
	buildStubPlugin(t)
	recipient, identity := stubKeys(t)

	ef, err := encfile.EncryptSecrets(
		map[string]string{"FOO": "bar"},
		map[string]string{"failsafe": recipient},
	)
	require.NoError(t, err)

	secrets, err := encfile.DecryptSecrets(ef, identity)
	require.NoError(t, err, "plugin identity should decrypt via fallback")
	require.Equal(t, "bar", secrets["FOO"])
}

// TestDecryptSecretsPluginAmongMany ensures the fallback picks the right wrapped
// key when several recipients (plugin + X25519) are present.
func TestDecryptSecretsPluginAmongMany(t *testing.T) {
	buildStubPlugin(t)
	recipient, identity := stubKeys(t)
	otherRecipient, _ := stubKeys(t)

	ef, err := encfile.EncryptSecrets(
		map[string]string{"FOO": "bar"},
		map[string]string{"failsafe": recipient, "other": otherRecipient},
	)
	require.NoError(t, err)

	secrets, err := encfile.DecryptSecrets(ef, identity)
	require.NoError(t, err)
	require.Equal(t, "bar", secrets["FOO"])
}

// TestReWrapWithPluginIdentity proves `users add/remove` works while
// authenticated with a hardware key (ReWrapDataKey goes through the same path).
func TestReWrapWithPluginIdentity(t *testing.T) {
	buildStubPlugin(t)
	recipient, identity := stubKeys(t)
	newRecipient, newIdentity := stubKeys(t)

	ef, err := encfile.EncryptSecrets(
		map[string]string{"FOO": "bar"},
		map[string]string{"failsafe": recipient},
	)
	require.NoError(t, err)

	// Add a second recipient while holding only the plugin identity.
	err = encfile.ReWrapDataKey(ef, map[string]string{
		"failsafe": recipient,
		"added":    newRecipient,
	}, identity)
	require.NoError(t, err)

	// The newly added recipient can now decrypt.
	secrets, err := encfile.DecryptSecrets(ef, newIdentity)
	require.NoError(t, err)
	require.Equal(t, "bar", secrets["FOO"])
}

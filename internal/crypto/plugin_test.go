package crypto_test

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/crypto"
)

// buildStubPlugin compiles the test-only age-plugin-shhtest binary into a temp
// dir and prepends it to PATH for the duration of the test, so the age plugin
// protocol is exercised for real (subprocess + stdin/stdout state machine).
func buildStubPlugin(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "age-plugin-shhtest")
	if runtime.GOOS == "windows" {
		bin += ".exe" // age resolves age-plugin-<name> via PATHEXT on Windows
	}
	out, err := exec.Command("go", "build", "-o", bin, "./testdata/age-plugin-shhtest").CombinedOutput()
	require.NoError(t, err, "build stub plugin: %s", out)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// stubKeys returns a matching (recipient, identity) pair for the stub plugin.
// The XOR key material rides inside the encodings, so the stub stays generic.
func stubKeys(t *testing.T) (recipient, identity string) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return plugin.EncodeRecipient("shhtest", key), plugin.EncodeIdentity("shhtest", key)
}

// TestPluginWrapUnwrapRoundTrip is the core end-to-end proof: shh wraps a data
// key to a *plugin* recipient and unwraps it with the matching *plugin*
// identity, driving the real age plugin protocol through our stub binary.
func TestPluginWrapUnwrapRoundTrip(t *testing.T) {
	buildStubPlugin(t)
	recipient, identity := stubKeys(t)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)

	wrapped, err := crypto.WrapDataKeyForRecipient(dataKey, recipient)
	require.NoError(t, err, "wrap to plugin recipient")

	got, err := crypto.UnwrapDataKey(wrapped, identity)
	require.NoError(t, err, "unwrap with plugin identity")
	require.Equal(t, dataKey, got)
}

// TestPluginWrongIdentityFails proves a non-matching plugin identity can't
// unwrap (the XOR key differs), i.e. we're really round-tripping crypto.
func TestPluginWrongIdentityFails(t *testing.T) {
	buildStubPlugin(t)
	recipient, _ := stubKeys(t)
	_, otherIdentity := stubKeys(t)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapDataKeyForRecipient(dataKey, recipient)
	require.NoError(t, err)

	got, err := crypto.UnwrapDataKey(wrapped, otherIdentity)
	require.Error(t, err)
	require.NotEqual(t, dataKey, got)
}

// --- Encoding-only behavior: no plugin binary on PATH required ---

func TestValidateRecipientAcceptsPluginAndX25519(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	recipient, _ := stubKeys(t)

	require.NoError(t, crypto.ValidateRecipient(id.Recipient().String()), "x25519")
	require.NoError(t, crypto.ValidateRecipient(recipient), "plugin")
	require.Error(t, crypto.ValidateRecipient("not-a-key"))
}

func TestValidateIdentityAcceptsPluginAndX25519(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	_, identity := stubKeys(t)

	require.NoError(t, crypto.ValidateIdentity(id.String()), "x25519")
	require.NoError(t, crypto.ValidateIdentity(identity), "plugin")
	require.Error(t, crypto.ValidateIdentity("not-a-key"))
}

func TestPublicKeyFromRejectsPluginIdentity(t *testing.T) {
	_, identity := stubKeys(t)
	_, err := crypto.PublicKeyFrom(identity)
	require.Error(t, err, "plugin identity has no locally-derivable recipient")

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	pub, err := crypto.PublicKeyFrom(id.String())
	require.NoError(t, err)
	require.Equal(t, id.Recipient().String(), pub)
}

func TestRecipientKind(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	kind, extractable := crypto.RecipientKind(id.Recipient().String())
	require.Equal(t, "x25519", kind)
	require.True(t, extractable, "native X25519 keys are extractable")

	recipient, _ := stubKeys(t)
	kind, extractable = crypto.RecipientKind(recipient)
	require.Equal(t, "shhtest", kind, "plugin name is reported")
	require.False(t, extractable, "plugin recipients are not extractable")
}

func TestIsPluginIdentity(t *testing.T) {
	_, identity := stubKeys(t)
	require.True(t, crypto.IsPluginIdentity(identity))

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.False(t, crypto.IsPluginIdentity(id.String()))
}

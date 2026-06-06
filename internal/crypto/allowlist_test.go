package crypto_test

import (
	"crypto/rand"
	"strings"
	"testing"

	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/crypto"
)

func encodePluginRecipient(t *testing.T, name string) string {
	t.Helper()
	data := make([]byte, 32)
	_, err := rand.Read(data)
	require.NoError(t, err)
	return plugin.EncodeRecipient(name, data)
}

// Untrusted recipients in .env.enc reach ParseRecipient, which would otherwise
// exec age-plugin-<name>. The allowlist must reject unknown plugin names BEFORE
// any binary is spawned.
func TestAllowlistRejectsUnknownPlugin(t *testing.T) {
	evil := encodePluginRecipient(t, "evil")

	require.Error(t, crypto.ValidateRecipient(evil), "unknown plugin recipient must fail validation")

	_, err := crypto.ParseRecipient(evil)
	require.Error(t, err, "ParseRecipient must refuse an unknown plugin")
	require.NotContains(t, strings.ToLower(err.Error()), "plugin not found",
		"must be rejected by the allowlist, not by a failed exec (which would mean we tried to run it)")
}

func TestAllowlistAllowsKnownPlugins(t *testing.T) {
	require.NoError(t, crypto.ValidateRecipient(encodePluginRecipient(t, "yubikey")))
	require.NoError(t, crypto.ValidateRecipient(encodePluginRecipient(t, "se")))
}

// The identity path also execs age-plugin-<name> (on decrypt). A disallowed
// plugin identity (e.g. via SHH_AGE_KEY) must be rejected before any exec.
func TestAllowlistRejectsUnknownPluginIdentity(t *testing.T) {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	require.NoError(t, err)
	evil := plugin.EncodeIdentity("evil", data)

	require.Error(t, crypto.ValidateIdentity(evil), "unknown plugin identity must fail validation")

	_, err = crypto.ParseIdentity(evil)
	require.Error(t, err)
	require.NotContains(t, strings.ToLower(err.Error()), "plugin not found",
		"must be rejected by the allowlist, not by a failed exec")
}

func TestAllowlistAllowsKnownPluginIdentity(t *testing.T) {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	require.NoError(t, err)
	require.NoError(t, crypto.ValidateIdentity(plugin.EncodeIdentity("yubikey", data)))
	require.NoError(t, crypto.ValidateIdentity(plugin.EncodeIdentity("se", data)))
}

func TestAllowlistEnvOverride(t *testing.T) {
	tpm := encodePluginRecipient(t, "tpm")
	require.Error(t, crypto.ValidateRecipient(tpm), "tpm not allowed by default")

	t.Setenv("SHH_ALLOWED_AGE_PLUGINS", "tpm, custom")
	require.NoError(t, crypto.ValidateRecipient(tpm), "env override should permit tpm")
}

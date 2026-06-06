package crypto

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/cockroachdb/errors"
)

// Plugin recipients cause age to exec age-plugin-<name> from PATH. Recipients
// are read from the committed (attacker-modifiable) .env.enc, so an unknown
// <name> is a code-execution vector. We only honor an allowlist of plugins shh
// actually supports; extend it explicitly via SHH_ALLOWED_AGE_PLUGINS (comma-
// separated) for other trusted plugins (e.g. tpm, fido).
func allowedPlugins() map[string]bool {
	allowed := map[string]bool{"yubikey": true, "se": true}
	for _, name := range strings.Split(os.Getenv("SHH_ALLOWED_AGE_PLUGINS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			allowed[name] = true
		}
	}
	return allowed
}

func pluginAllowed(name string) bool { return allowedPlugins()[name] }

// EnsureRecipientAllowed errors only when s is a well-formed plugin recipient for
// a plugin that is not on the allowlist. Malformed or X25519 recipients pass —
// they fail safely downstream / are caught by the MAC. This narrow gate exists
// solely to stop a disallowed plugin name (from an untrusted file) reaching age's
// plugin exec; use it at load time without rejecting otherwise-handled inputs.
func EnsureRecipientAllowed(s string) error {
	if name, _, err := plugin.ParseRecipient(s); err == nil && !pluginAllowed(name) {
		return errors.Newf("age plugin %q is not allowed (set SHH_ALLOWED_AGE_PLUGINS to permit it)", name)
	}
	return nil
}

// This file teaches shh's age layer to speak the age *plugin* protocol in
// addition to native X25519 keys, so a recipient/identity can be backed by
// non-extractable hardware (YubiKey via age-plugin-yubikey, Apple Secure Enclave
// via age-plugin-se, etc.) instead of a copyable secret.
//
// Two flavors of helper:
//   - Parse*    construct a working age.Recipient/age.Identity. For plugin keys
//               this shells out to the plugin binary (and, for decryption, the
//               hardware) — use only when you're about to encrypt/decrypt.
//   - Validate* check the *encoding* only, never invoking a binary or hardware.
//               Use for cheap "is this a key?" checks (CLI input, env vars).

// pluginUI routes plugin prompts ("touch your YubiKey", PIN entry, …) to stderr,
// keeping stdout clean for piped secrets.
func pluginUI() *plugin.ClientUI {
	toStderr := func(format string, v ...any) { fmt.Fprintf(os.Stderr, format+"\n", v...) }
	return plugin.NewTerminalUI(toStderr, toStderr)
}

// ParseRecipient parses an age recipient, supporting plugin recipients (e.g.
// age1yubikey1…, age1se1…) as well as native X25519 (age1…). A plugin recipient
// requires its plugin binary to be installed (but not the hardware — encrypting
// to a recipient is public-key only).
func ParseRecipient(s string) (age.Recipient, error) {
	if name, _, err := plugin.ParseRecipient(s); err == nil {
		// Allowlist check BEFORE NewRecipient, which would exec age-plugin-<name>.
		if !pluginAllowed(name) {
			return nil, errors.Newf("recipient uses age plugin %q, which is not allowed (set SHH_ALLOWED_AGE_PLUGINS to permit it)", name)
		}
		r, err := plugin.NewRecipient(s, pluginUI())
		if err != nil {
			return nil, errors.Wrapf(err, "plugin recipient %s", s)
		}
		return r, nil
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, errors.Wrapf(err, "parse recipient %s", s)
	}
	return r, nil
}

// ParseIdentity parses an age identity, supporting plugin identities
// (AGE-PLUGIN-YUBIKEY-…, AGE-PLUGIN-SE-…) as well as native X25519
// (AGE-SECRET-KEY-…). Using a plugin identity to decrypt invokes the plugin and
// its hardware (touch/PIN/biometric).
func ParseIdentity(s string) (age.Identity, error) {
	if _, _, err := plugin.ParseIdentity(s); err == nil {
		id, err := plugin.NewIdentity(s, pluginUI())
		if err != nil {
			return nil, errors.Wrap(err, "parse plugin identity")
		}
		return id, nil
	}
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, errors.Wrap(err, "parse age identity")
	}
	return id, nil
}

// ValidateRecipient reports whether s is a well-formed age recipient (plugin or
// X25519). Encoding-only: it does not run a plugin binary.
func ValidateRecipient(s string) error {
	if name, _, err := plugin.ParseRecipient(s); err == nil {
		if !pluginAllowed(name) {
			return errors.Newf("age plugin %q is not allowed (set SHH_ALLOWED_AGE_PLUGINS to permit it)", name)
		}
		return nil
	}
	if _, err := age.ParseX25519Recipient(s); err == nil {
		return nil
	}
	return errors.Newf("not a valid age recipient: %q", s)
}

// ValidateIdentity reports whether s is a well-formed age identity (plugin or
// X25519). Encoding-only: it does not run a plugin binary or touch hardware, so
// it's safe for validating env vars / CLI input cheaply.
func ValidateIdentity(s string) error {
	if _, _, err := plugin.ParseIdentity(s); err == nil {
		return nil
	}
	if _, err := age.ParseX25519Identity(s); err == nil {
		return nil
	}
	return errors.Newf("not a valid age identity")
}

// IsPluginIdentity reports whether s is a plugin identity (AGE-PLUGIN-…) rather
// than a native X25519 secret key.
func IsPluginIdentity(s string) bool {
	_, _, err := plugin.ParseIdentity(s)
	return err == nil
}

// RecipientKind classifies a recipient by its *encoding* — the authoritative,
// un-spoofable signal, derived from the key itself (never stored): "x25519" for
// a native key, or the plugin name (e.g. "yubikey", "se") for a plugin
// recipient. extractable is true only for x25519: that's the form whose private
// key shh itself can hold as a copyable secret, so it's the form the
// rotation-on-leak rule applies to. Plugin recipients delegate extractability to
// their backing (hardware for yubikey/se), so they're reported not-extractable.
func RecipientKind(pubKey string) (kind string, extractable bool) {
	if name, _, err := plugin.ParseRecipient(pubKey); err == nil {
		return name, false
	}
	return "x25519", true
}

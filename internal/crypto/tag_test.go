package crypto

import (
	"bytes"
	"testing"

	"github.com/stefanpenner/shh/internal/tagtest"
)

// A tag recipient must work with an empty plugin allowlist: age wraps to it
// natively, so nothing is exec'd.
func TestTagRecipientNative(t *testing.T) {
	t.Setenv("SHH_ALLOWED_AGE_PLUGINS", "")
	id := tagtest.New("shh-tag-test")
	rec := id.Recipient().String()

	if !IsTagRecipient(rec) {
		t.Fatalf("IsTagRecipient(%q) = false", rec)
	}
	if err := ValidateRecipient(rec); err != nil {
		t.Fatalf("ValidateRecipient: %v", err)
	}
	if err := EnsureRecipientAllowed(rec); err != nil {
		t.Fatalf("EnsureRecipientAllowed: %v", err)
	}
	if kind, extractable := RecipientKind(rec); kind != "tag" || extractable {
		t.Fatalf("RecipientKind = %q, %v; want tag, false", kind, extractable)
	}
	if _, err := ParseRecipient(rec); err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}

	key := bytes.Repeat([]byte{7}, 32)
	wrapped, err := WrapDataKeyForRecipient(key, rec)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := UnwrapDataKeyWith(wrapped, id)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unwrapped key differs")
	}
	if _, err := UnwrapDataKeyWith(wrapped, tagtest.New("someone-else")); err == nil {
		t.Fatal("a different tag identity unwrapped the key")
	}
}

// Other plugin names stay gated; the tag carve-out is by encoding, not prefix.
func TestTagCarveOutIsNarrow(t *testing.T) {
	t.Setenv("SHH_ALLOWED_AGE_PLUGINS", "")
	for _, s := range []string{
		"age1tag1notvalidbech32",
		"age1tag1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
	} {
		if IsTagRecipient(s) {
			t.Errorf("IsTagRecipient(%q) = true", s)
		}
		if ValidateRecipient(s) == nil {
			t.Errorf("ValidateRecipient(%q) accepted a malformed tag key", s)
		}
	}
}

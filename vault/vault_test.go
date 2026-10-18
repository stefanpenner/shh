package vault_test

import (
	"testing"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/tagtest"
	"github.com/stefanpenner/shh/vault"
)

func sealed(t *testing.T, recipients map[string]string) []byte {
	t.Helper()
	ef, err := encfile.EncryptSecrets(map[string]string{"A": "one", "B": "two"}, recipients)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	b, err := encfile.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestOpenWithTagIdentity(t *testing.T) {
	t.Setenv("SHH_ALLOWED_AGE_PLUGINS", "")
	node := tagtest.New("node")
	other := tagtest.New("other")
	file := sealed(t, map[string]string{
		"shh-user://a-other": other.Recipient().String(),
		"shh-user://node":    node.Recipient().String(),
	})

	v, err := vault.Open(file, node)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := v.Names(); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("names = %v", got)
	}
	if s, err := v.Secret("B"); err != nil || s != "two" {
		t.Fatalf("secret B = %q, %v", s, err)
	}
	if _, err := v.Secret("C"); err == nil {
		t.Fatal("missing name returned a value")
	}
	v.Close()
	v.Close()
	if _, err := v.Secret("A"); err == nil {
		t.Fatal("closed vault returned a value")
	}
}

func TestOpenFailsClosed(t *testing.T) {
	node := tagtest.New("node")
	file := sealed(t, map[string]string{"shh-user://other": tagtest.New("other").Recipient().String()})
	if _, err := vault.Open(file, node); err == nil {
		t.Fatal("opened a vault the identity is not a recipient of")
	}
	if _, err := vault.Open(nil, node); err == nil {
		t.Fatal("opened an empty file")
	}
	if _, err := vault.Open(file, nil); err == nil {
		t.Fatal("opened with a nil identity")
	}

	// A flipped byte in a secret value must fail the MAC before any value is read.
	good := sealed(t, map[string]string{"shh-user://node": node.Recipient().String()})
	ef, err := encfile.LoadFromBytes(good)
	if err != nil {
		t.Fatal(err)
	}
	ef.Secrets["A"] = ef.Secrets["B"]
	bad, err := encfile.Marshal(ef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Open(bad, node); err == nil {
		t.Fatal("opened a vault with a tampered value")
	}
}

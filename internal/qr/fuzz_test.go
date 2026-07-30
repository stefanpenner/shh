package qr

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

// FuzzNormalizePayload: never panic; empty or short output for garbage.
func FuzzNormalizePayload(f *testing.F) {
	f.Add("")
	f.Add("AGE-SECRET-KEY-1")
	f.Add("https://evil.example/")
	f.Add("SHH_AGE_KEY=AGE-SECRET-KEY-1ABC")
	f.Add("# comment\nfoo\n")
	f.Add(string([]byte{0, 1, 2, 255}))
	f.Fuzz(func(t *testing.T, in string) {
		out := NormalizePayload(in)
		if len(out) > len(in)+32 {
			t.Fatalf("normalize grew payload unexpectedly: %d -> %d", len(in), len(out))
		}
		// Must not contain NUL after normalize (we drop such inputs).
		for i := 0; i < len(out); i++ {
			if out[i] == 0 {
				t.Fatal("NUL in normalized payload")
			}
		}
	})
}

// FuzzParseExtractableSecret: garbage never panics; only real secrets succeed.
func FuzzParseExtractableSecret(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(id.String())
	f.Add("https://phish")
	f.Add("")
	f.Add(string(make([]byte, 10000)))
	f.Fuzz(func(t *testing.T, in string) {
		secret, err := ParseExtractableSecret(in)
		if err != nil {
			return
		}
		// If accepted, must round-trip as extractable and re-parse.
		if !IsExtractableAgeSecret(secret) {
			t.Fatalf("accepted non-extractable: %q", secret)
		}
		again, err2 := ParseExtractableSecret(secret)
		if err2 != nil || again != secret {
			t.Fatalf("accepted secret not stable under re-parse")
		}
	})
}

// FuzzDecodePNG: random bytes must not panic.
func FuzzDecodePNG(f *testing.F) {
	// Seed with a valid QR of a real secret.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	var good bytes.Buffer
	if err := EncodePNG(id.String(), &good); err != nil {
		f.Fatal(err)
	}
	f.Add(good.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x89, 0x50, 0x4e, 0x47}) // PNG magic only
	f.Add(bytes.Repeat([]byte{0xff}, 1024))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxImageBytes+1024 {
			data = data[:MaxImageBytes+1024]
		}
		_, _ = DecodePNG(data) // err OK; panic not OK
	})
}

// FuzzEncodeDecodeRoundTrip: only valid secrets encode; then decode matches.
func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(id.String())
	f.Fuzz(func(t *testing.T, candidate string) {
		// Only fuzz *around* valid secrets: if Encode accepts, Decode must match.
		var buf bytes.Buffer
		if err := EncodePNG(candidate, &buf); err != nil {
			return
		}
		got, err := DecodePNG(buf.Bytes())
		if err != nil {
			t.Fatalf("encode succeeded but decode failed: %v", err)
		}
		want, err := ParseExtractableSecret(candidate)
		if err != nil {
			t.Fatalf("encode accepted invalid secret")
		}
		if got != want {
			t.Fatalf("round-trip mismatch")
		}
	})
}

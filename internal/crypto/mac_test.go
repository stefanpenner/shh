package crypto

import (
	"crypto/hmac"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeMAC_Tampering(t *testing.T) {
	dataKey, _ := GenerateDataKey()
	baseSecrets := map[string]string{"A": "1"}
	baseRecipients := map[string]string{"alice": "age1aaa"}
	baseWrappedKeys := map[string]string{"alice": "wk1"}

	baseMac := ComputeMAC(dataKey, 2, baseWrappedKeys, baseRecipients, baseSecrets)

	tests := []struct {
		name        string
		version     int
		wrappedKeys map[string]string
		recipients  map[string]string
		secrets     map[string]string
		wantSame    bool
	}{
		{"identical", 2, baseWrappedKeys, baseRecipients, baseSecrets, true},
		{"different secrets", 2, baseWrappedKeys, baseRecipients, map[string]string{"A": "2"}, false},
		{"added recipient", 2, baseWrappedKeys, map[string]string{"alice": "age1aaa", "eve": "age1eve"}, baseSecrets, false},
		{"different version", 99, baseWrappedKeys, baseRecipients, baseSecrets, false},
		{"different wrapped key", 2, map[string]string{"alice": "wk2"}, baseRecipients, baseSecrets, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac := ComputeMAC(dataKey, tt.version, tt.wrappedKeys, tt.recipients, tt.secrets)
			if tt.wantSame {
				assert.Equal(t, baseMac, mac)
			} else {
				assert.NotEqual(t, baseMac, mac)
			}
		})
	}
}

func TestComputeMAC_ConstantTimeComparison(t *testing.T) {
	dataKey, _ := GenerateDataKey()
	secrets := map[string]string{"A": "1"}
	recipients := map[string]string{"alice": "age1aaa"}
	wrappedKeys := map[string]string{"alice": "wk1"}
	mac := ComputeMAC(dataKey, 2, wrappedKeys, recipients, secrets)

	assert.True(t, hmac.Equal([]byte(mac), []byte(mac)))
	assert.False(t, hmac.Equal([]byte(mac), []byte("wrong")))
}

func FuzzEncryptDecryptValue(f *testing.F) {
	f.Add("hello", "KEY")
	f.Add("", "")
	f.Add("p@ss w0rd!#$%^&*()", "MY_SECRET")
	f.Fuzz(func(t *testing.T, plaintext, keyName string) {
		dataKey, err := GenerateDataKey()
		if err != nil {
			t.Skip()
		}
		enc, err := EncryptValue(dataKey, keyName, plaintext)
		if err != nil {
			t.Skip()
		}
		dec, err := DecryptValue(dataKey, keyName, enc)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if dec != plaintext {
			t.Fatalf("roundtrip mismatch: got %q, want %q", dec, plaintext)
		}
	})
}

func FuzzComputeMAC(f *testing.F) {
	f.Add("key1", "val1")
	f.Add("", "")
	f.Add("A\x00B", "val")
	f.Fuzz(func(t *testing.T, k, v string) {
		dataKey, err := GenerateDataKey()
		if err != nil {
			t.Skip()
		}
		secrets := map[string]string{k: v}
		recipients := map[string]string{"alice": "age1aaa"}
		wrappedKeys := map[string]string{"alice": "wk1"}
		mac1 := ComputeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
		mac2 := ComputeMAC(dataKey, 2, wrappedKeys, recipients, secrets)
		if mac1 != mac2 {
			t.Fatal("MAC should be deterministic")
		}
	})
}

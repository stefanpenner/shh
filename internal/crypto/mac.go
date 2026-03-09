package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/stefanpenner/shh/internal/envutil"
)

// ComputeMACv1 computes HMAC-SHA256 for v1 file format (single wrapped data key).
func ComputeMACv1(dataKey []byte, version int, wrappedDataKey string, recipients map[string]string, secrets map[string]string) string {
	mac := hmac.New(sha256.New, dataKey)
	fmt.Fprintf(mac, "version:%d\x00", version)
	mac.Write([]byte("data_key:"))
	mac.Write([]byte(wrappedDataKey))
	mac.Write([]byte{0})
	for _, name := range envutil.SortedKeys(recipients) {
		mac.Write([]byte("recipient:"))
		mac.Write([]byte(name))
		mac.Write([]byte{0})
		mac.Write([]byte(recipients[name]))
		mac.Write([]byte{0})
	}
	for _, k := range envutil.SortedKeys(secrets) {
		mac.Write([]byte(k))
		mac.Write([]byte{0})
		mac.Write([]byte(secrets[k]))
		mac.Write([]byte{0})
	}
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// ComputeMAC computes HMAC-SHA256 over all file fields for v2 format (per-recipient wrapped keys).
func ComputeMAC(dataKey []byte, version int, wrappedKeys map[string]string, recipients map[string]string, secrets map[string]string) string {
	mac := hmac.New(sha256.New, dataKey)
	fmt.Fprintf(mac, "version:%d\x00", version)
	for _, name := range envutil.SortedKeys(wrappedKeys) {
		mac.Write([]byte("wrapped_key:"))
		mac.Write([]byte(name))
		mac.Write([]byte{0})
		mac.Write([]byte(wrappedKeys[name]))
		mac.Write([]byte{0})
	}
	for _, name := range envutil.SortedKeys(recipients) {
		mac.Write([]byte("recipient:"))
		mac.Write([]byte(name))
		mac.Write([]byte{0})
		mac.Write([]byte(recipients[name]))
		mac.Write([]byte{0})
	}
	for _, k := range envutil.SortedKeys(secrets) {
		mac.Write([]byte(k))
		mac.Write([]byte{0})
		mac.Write([]byte(secrets[k]))
		mac.Write([]byte{0})
	}
	return fmt.Sprintf("%x", mac.Sum(nil))
}

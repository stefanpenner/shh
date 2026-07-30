// Package qr encodes and decodes age recovery identities as QR codes for
// paper / 1Password cold backup (Ring 0).
//
// Security model (aligned with offline recovery + QR threat guidance):
//   - Payload is offline plaintext of an extractable age secret (AGE-SECRET-KEY-…).
//   - Encode rejects URLs and non-identity data (no "dynamic QR" / shortener phishing).
//   - Decode bounds image size (no giant-file DoS) and re-validates payload.
//   - Round-trip Encode→Decode preserves the secret exactly (Go tests + fuzz).
//
// Crypto of .env.enc itself is unchanged; this is only the recovery *carrier*.
package qr

import (
	"bytes"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	goqrcode "github.com/skip2/go-qrcode"

	"github.com/stefanpenner/shh/internal/crypto"
)

// Bounds — hostile-input containment for untrusted QR images / paste.
const (
	// MaxPayloadLen is well above a native age secret (~74) and below abuse.
	MaxPayloadLen = 256
	// MaxImageBytes rejects multi‑MB images before full decode.
	MaxImageBytes = 2 << 20 // 2 MiB
	// MaxImageDim caps width/height after decode (pixel bomb mitigation).
	MaxImageDim = 4096
)

// NormalizePayload extracts the first useful line from QR/text paste input:
// trims space, skips comments, strips SHH_AGE_KEY= / export prefixes.
func NormalizePayload(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Reject NULs early (not valid in age identities; common fuzz junk).
	if strings.ContainsRune(s, 0) {
		return ""
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		if strings.HasPrefix(line, "SHH_AGE_KEY=") {
			line = strings.TrimPrefix(line, "SHH_AGE_KEY=")
			line = strings.Trim(line, `"'`)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return line
	}
	return ""
}

// looksLikeURL catches quishing-style QR payloads (https://…, javascript:, …).
func looksLikeURL(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, pfx := range []string{
		"http://", "https://", "javascript:", "data:", "file:",
		"//", "www.",
	} {
		if strings.HasPrefix(lower, pfx) {
			return true
		}
	}
	return false
}

// IsExtractableAgeSecret reports a native X25519 secret (paper-recoverable).
// Plugin stubs (AGE-PLUGIN-…) are not useful as paper recovery roots.
func IsExtractableAgeSecret(s string) bool {
	s = NormalizePayload(s)
	if s == "" || looksLikeURL(s) {
		return false
	}
	if !strings.HasPrefix(s, "AGE-SECRET-KEY-") {
		return false
	}
	if len(s) > MaxPayloadLen {
		return false
	}
	return crypto.ValidateIdentity(s) == nil
}

// IsAgeIdentity is a broader check (secret or allowed plugin). Prefer
// IsExtractableAgeSecret for recovery QR encode/login.
func IsAgeIdentity(s string) bool {
	s = NormalizePayload(s)
	if s == "" || looksLikeURL(s) || len(s) > MaxPayloadLen {
		return false
	}
	return crypto.ValidateIdentity(s) == nil
}

// ParseExtractableSecret normalizes and cryptographically validates a recovery
// payload. Returns the canonical secret string or an error (evil/garbage input).
func ParseExtractableSecret(raw string) (string, error) {
	s := NormalizePayload(raw)
	if s == "" {
		return "", errors.New("empty recovery payload")
	}
	if looksLikeURL(s) {
		return "", errors.New("refusing URL/QR phishing payload (expected AGE-SECRET-KEY-…)")
	}
	if len(s) > MaxPayloadLen {
		return "", errors.Newf("payload too long (%d > %d)", len(s), MaxPayloadLen)
	}
	if !strings.HasPrefix(s, "AGE-SECRET-KEY-") {
		return "", errors.New("not an extractable age secret (expected AGE-SECRET-KEY-…)")
	}
	if !utf8.ValidString(s) {
		return "", errors.New("payload is not valid UTF-8")
	}
	if err := crypto.ValidateIdentity(s); err != nil {
		return "", errors.Wrap(err, "invalid age secret")
	}
	return s, nil
}

// ChecksumHint returns a short human-checkable fragment (not a crypto MAC).
func ChecksumHint(payload string) string {
	payload = NormalizePayload(payload)
	if payload == "" {
		return ""
	}
	body := payload
	const pfx = "AGE-SECRET-KEY-1"
	if strings.HasPrefix(body, pfx) && len(body) > len(pfx) {
		body = body[len(pfx):]
	}
	up := strings.ToUpper(body)
	if len(up) <= 8 {
		return up
	}
	return up[:4] + "…" + up[len(up)-4:]
}

// EncodePNG writes a PNG QR for an extractable recovery secret.
func EncodePNG(payload string, w io.Writer) error {
	secret, err := ParseExtractableSecret(payload)
	if err != nil {
		return errors.Wrap(err, "qr encode")
	}
	// High error correction — paper print + phone camera (offline recovery).
	code, err := goqrcode.New(secret, goqrcode.High)
	if err != nil {
		return errors.Wrap(err, "qr encode")
	}
	return code.Write(512, w)
}

// EncodeFile writes a PNG QR to path (0600).
func EncodeFile(payload, path string) error {
	var buf bytes.Buffer
	if err := EncodePNG(payload, &buf); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// EncodeANSI returns a compact half-block QR string for terminal display.
func EncodeANSI(payload string) (string, error) {
	secret, err := ParseExtractableSecret(payload)
	if err != nil {
		return "", errors.Wrap(err, "qr encode")
	}
	code, err := goqrcode.New(secret, goqrcode.High)
	if err != nil {
		return "", errors.Wrap(err, "qr encode")
	}
	return code.ToSmallString(false), nil
}

// DecodePNG decodes and validates a recovery secret from PNG bytes.
func DecodePNG(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty image")
	}
	if len(data) > MaxImageBytes {
		return "", errors.Newf("image too large (%d > %d bytes)", len(data), MaxImageBytes)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.Wrap(err, "png decode")
	}
	return DecodeImage(img)
}

// DecodeFile decodes a recovery secret from a PNG/JPEG file with size bounds.
func DecodeFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Size() > MaxImageBytes {
		return "", errors.Newf("image too large (%d > %d bytes)", st.Size(), MaxImageBytes)
	}
	// #nosec G304 -- path is a CLI argument supplied by the operator
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Bound read even if file grows (TOCTOU) via LimitReader.
	limited := io.LimitReader(f, MaxImageBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(data) > MaxImageBytes {
		return "", errors.Newf("image too large (>%d bytes)", MaxImageBytes)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.Wrap(err, "image decode")
	}
	return DecodeImage(img)
}

// DecodeImage reads the first QR payload and requires an extractable age secret.
func DecodeImage(img image.Image) (string, error) {
	if img == nil {
		return "", errors.New("nil image")
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return "", errors.New("empty image bounds")
	}
	if w > MaxImageDim || h > MaxImageDim {
		return "", errors.Newf("image dimensions too large (%dx%d > %d)", w, h, MaxImageDim)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", errors.Wrap(err, "qr bitmap")
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", errors.Wrap(err, "qr decode")
	}
	return ParseExtractableSecret(result.GetText())
}

// Package qr encodes and decodes age recovery identities as QR codes for
// paper / 1Password cold backup (Ring 0). Round-trip: Encode* → Decode* must
// preserve the AGE-SECRET-KEY-… payload exactly.
package qr

import (
	"bytes"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	goqrcode "github.com/skip2/go-qrcode"
)

// NormalizePayload extracts the first useful line from QR/text paste input:
// trims space, skips comments, strips SHH_AGE_KEY= / export prefixes.
func NormalizePayload(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
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
		return strings.TrimSpace(line)
	}
	return ""
}

// IsAgeIdentity reports whether s looks like an age identity after normalize.
func IsAgeIdentity(s string) bool {
	s = NormalizePayload(s)
	return strings.HasPrefix(s, "AGE-SECRET-KEY-") || strings.HasPrefix(s, "AGE-PLUGIN-")
}

// ChecksumHint returns a short human-checkable fragment of the payload (not a
// cryptographic MAC — only for eyeballing paper cards). Skips the fixed
// AGE-SECRET-KEY-1 prefix so the hint varies per key.
func ChecksumHint(payload string) string {
	payload = NormalizePayload(payload)
	if payload == "" {
		return ""
	}
	body := payload
	for _, pfx := range []string{"AGE-SECRET-KEY-1", "AGE-PLUGIN-"} {
		if strings.HasPrefix(strings.ToUpper(body), pfx) || strings.HasPrefix(body, pfx) {
			// strip case-insensitively for SECRET form
			if len(body) > len(pfx) {
				body = body[len(pfx):]
			}
			break
		}
	}
	up := strings.ToUpper(body)
	if len(up) <= 8 {
		return up
	}
	return up[:4] + "…" + up[len(up)-4:]
}

// EncodePNG writes a PNG QR code for payload to w.
func EncodePNG(payload string, w io.Writer) error {
	payload = NormalizePayload(payload)
	if payload == "" {
		return errors.New("empty QR payload")
	}
	// Medium recovery — good balance for paper print + phone scan.
	code, err := goqrcode.New(payload, goqrcode.Medium)
	if err != nil {
		return errors.Wrap(err, "qr encode")
	}
	// 512px is plenty for paper; library uses size as PNG dimension.
	return code.Write(512, w)
}

// EncodeFile writes a PNG QR code to path (0600).
func EncodeFile(payload, path string) error {
	var buf bytes.Buffer
	if err := EncodePNG(payload, &buf); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// EncodeANSI returns a compact half-block QR string for terminal display.
func EncodeANSI(payload string) (string, error) {
	payload = NormalizePayload(payload)
	if payload == "" {
		return "", errors.New("empty QR payload")
	}
	code, err := goqrcode.New(payload, goqrcode.Medium)
	if err != nil {
		return "", errors.Wrap(err, "qr encode")
	}
	// false = black on white; works on light and most dark terminals with inversion.
	return code.ToSmallString(false), nil
}

// DecodePNG decodes the first QR code from PNG bytes.
func DecodePNG(data []byte) (string, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.Wrap(err, "png decode")
	}
	return DecodeImage(img)
}

// DecodeFile decodes a QR code from a PNG/JPEG image file.
func DecodeFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is a CLI argument
	if err != nil {
		return "", err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return "", errors.Wrap(err, "image decode")
	}
	return DecodeImage(img)
}

// DecodeImage reads the first QR payload from img and normalizes it.
func DecodeImage(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", errors.Wrap(err, "qr bitmap")
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", errors.Wrap(err, "qr decode")
	}
	payload := NormalizePayload(result.GetText())
	if payload == "" {
		return "", errors.New("qr payload empty after normalize")
	}
	return payload, nil
}

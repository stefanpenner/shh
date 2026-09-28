package qr

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"image"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	goqrcode "github.com/skip2/go-qrcode"
)

// Paper QR frames for a gzip-compressed vault. Each code is text:
//
//	SHHENV1 <total> <index> <sum> <body>
//
// total and index are 1-based. sum is 8 hex chars of SHA-256(gzip).
// body is base32 of one slice of the gzip stream. The sum binds the sheet.
// It is not the vault MAC.
//
// One code may use QR version 40 at low error correction. That is 4,296
// alphanumeric characters. The gzip payload in one code is 2,670 bytes.
// A smaller stream uses a smaller version.
const (
	vaultMagic = "SHHENV1"
	// rawChunk is the largest gzip slice whose version-40 code this reader
	// scans. The QR standard allows 2,670 bytes here. Denser symbols decode
	// as version 41 and fail.
	rawChunk = 2580
	// MaxParts caps a sheet so a hostile code cannot ask for a huge assembly.
	MaxParts = 16
	// MaxVaultBytes is the vault size before gzip.
	MaxVaultBytes = 64 << 10
	maxFrameChars = 4296
)

var vaultEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Frame is one scanned code.
type Frame struct {
	Total int
	Index int
	Sum   string
	Data  []byte
}

// SplitVault slices a gzip stream into frames.
func SplitVault(payload []byte) ([]Frame, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty vault")
	}
	if len(payload) > MaxParts*rawChunk {
		return nil, errors.Newf("compressed vault is too large for paper QR (%d bytes)", len(payload))
	}
	sum := vaultSum(payload)
	total := (len(payload) + rawChunk - 1) / rawChunk
	frames := make([]Frame, 0, total)
	for i := 0; i < total; i++ {
		lo := i * rawChunk
		hi := lo + rawChunk
		if hi > len(payload) {
			hi = len(payload)
		}
		frames = append(frames, Frame{
			Total: total,
			Index: i + 1,
			Sum:   sum,
			Data:  append([]byte(nil), payload[lo:hi]...),
		})
	}
	return frames, nil
}

// FormatFrame renders one frame. Encode checks that the bytes fit in one QR code.
func FormatFrame(f Frame) (string, error) {
	if err := checkFrameMeta(f.Total, f.Index, f.Sum); err != nil {
		return "", err
	}
	if len(f.Data) == 0 || len(f.Data) > rawChunk {
		return "", errors.New("bad frame size")
	}
	body := vaultEncoding.EncodeToString(f.Data)
	text := vaultMagic + " " + strconv.Itoa(f.Total) + " " + strconv.Itoa(f.Index) + " " + f.Sum + " " + body
	if len(text) > maxFrameChars {
		return "", errors.New("frame text is too long")
	}
	return text, nil
}

// ParseFrame reads one scanned code. It rejects URLs and any other shape.
func ParseFrame(raw string) (Frame, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Frame{}, errors.New("empty QR")
	}
	if looksLikeURL(s) {
		return Frame{}, errors.New("refusing URL QR")
	}
	if len(s) > maxFrameChars {
		return Frame{}, errors.New("QR text is too long")
	}
	parts := strings.Fields(s)
	if len(parts) != 5 || !strings.EqualFold(parts[0], vaultMagic) {
		return Frame{}, errors.New("not a vault QR")
	}
	total, err := strconv.Atoi(parts[1])
	if err != nil {
		return Frame{}, errors.New("bad vault QR total")
	}
	index, err := strconv.Atoi(parts[2])
	if err != nil {
		return Frame{}, errors.New("bad vault QR index")
	}
	sum := strings.ToUpper(parts[3])
	if err := checkFrameMeta(total, index, sum); err != nil {
		return Frame{}, err
	}
	data, err := vaultEncoding.DecodeString(parts[4])
	if err != nil {
		return Frame{}, errors.New("bad vault QR body")
	}
	if len(data) == 0 || len(data) > rawChunk {
		return Frame{}, errors.New("bad frame size")
	}
	return Frame{Total: total, Index: index, Sum: sum, Data: data}, nil
}

// Assemble joins a complete sheet. Every index from 1 to total must appear once.
func Assemble(frames []Frame) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errors.New("no vault QR codes")
	}
	total := frames[0].Total
	sum := frames[0].Sum
	if total < 1 || total > MaxParts || len(frames) != total {
		return nil, errors.Newf("need %d vault QR codes, got %d", total, len(frames))
	}
	parts := make([][]byte, total)
	seen := make([]bool, total)
	for _, f := range frames {
		if f.Total != total || f.Sum != sum {
			return nil, errors.New("vault QR codes are not one sheet")
		}
		if f.Index < 1 || f.Index > total || seen[f.Index-1] {
			return nil, errors.New("duplicate or bad vault QR index")
		}
		seen[f.Index-1] = true
		parts[f.Index-1] = f.Data
	}
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	raw := buf.Bytes()
	if vaultSum(raw) != sum {
		return nil, errors.New("vault QR sheet does not match its sum")
	}
	return raw, nil
}

// EncodeVaultPNGs gzips the vault and returns one PNG per frame, in index order.
func EncodeVaultPNGs(vault []byte) ([][]byte, error) {
	payload, err := gzipVault(vault)
	if err != nil {
		return nil, err
	}
	frames, err := SplitVault(payload)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(frames))
	for _, f := range frames {
		text, err := FormatFrame(f)
		if err != nil {
			return nil, err
		}
		code, err := goqrcode.New(text, goqrcode.Low)
		if err != nil {
			return nil, errors.Wrap(err, "qr encode")
		}
		if code.VersionNumber > 40 {
			return nil, errors.Newf("QR version %d is above the QR maximum", code.VersionNumber)
		}
		var buf bytes.Buffer
		if err := code.Write(qrPixelSize(code.VersionNumber), &buf); err != nil {
			return nil, errors.Wrap(err, "qr png")
		}
		out = append(out, buf.Bytes())
	}
	return out, nil
}

// WriteVaultQRs writes 01.png, 02.png, ... into dir at mode 0600.
func WriteVaultQRs(vault []byte, dir string) (int, error) {
	pngs, err := EncodeVaultPNGs(vault)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, errors.Wrap(err, "create QR directory")
	}
	for i, png := range pngs {
		path := filepath.Join(dir, frameName(i+1))
		if err := os.WriteFile(path, png, 0o600); err != nil {
			return 0, errors.Wrap(err, "write QR")
		}
	}
	return len(pngs), nil
}

// ReadVaultQRs loads one PNG or every image in a directory and assembles the vault.
func ReadVaultQRs(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var paths []string
	if !st.IsDir() {
		paths = []string{path}
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !isImageName(e.Name()) {
				continue
			}
			paths = append(paths, filepath.Join(path, e.Name()))
			if len(paths) > MaxParts {
				return nil, errors.Newf("more than %d images", MaxParts)
			}
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("no QR images")
	}
	frames := make([]Frame, 0, len(paths))
	for _, p := range paths {
		text, err := decodeFileText(p)
		if err != nil {
			return nil, errors.Wrapf(err, "read %s", filepath.Base(p))
		}
		f, err := ParseFrame(text)
		if err != nil {
			return nil, errors.Wrapf(err, "parse %s", filepath.Base(p))
		}
		frames = append(frames, f)
	}
	packed, err := Assemble(frames)
	if err != nil {
		return nil, err
	}
	return gunzipVault(packed)
}

func qrPixelSize(version int) int {
	modules := 21 + (version-1)*4
	px := (modules + 8) * 8
	if px < 256 {
		return 256
	}
	return px
}

func frameName(index int) string {
	return strconv.Itoa(index/10) + strconv.Itoa(index%10) + ".png"
}

func isImageName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg":
		return true
	default:
		return false
	}
}

func vaultSum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return strings.ToUpper(hex.EncodeToString(sum[:4]))
}

func checkFrameMeta(total, index int, sum string) error {
	if total < 1 || total > MaxParts {
		return errors.New("bad vault QR total")
	}
	if index < 1 || index > total {
		return errors.New("bad vault QR index")
	}
	if len(sum) != 8 {
		return errors.New("bad vault QR sum")
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return errors.New("bad vault QR sum")
	}
	return nil
}

func gzipVault(vault []byte) ([]byte, error) {
	if len(vault) == 0 {
		return nil, errors.New("empty vault")
	}
	if len(vault) > MaxVaultBytes {
		return nil, errors.Newf("vault is too large for paper QR (%d bytes, max %d)", len(vault), MaxVaultBytes)
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(vault); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipVault(payload []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("vault QR is not gzip data")
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, MaxVaultBytes+1))
	if err != nil {
		return nil, errors.New("vault QR gzip is invalid")
	}
	if len(out) > MaxVaultBytes {
		return nil, errors.New("vault QR expands too far")
	}
	if len(out) == 0 {
		return nil, errors.New("empty vault")
	}
	return out, nil
}

func decodeFileText(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Size() > MaxImageBytes {
		return "", errors.Newf("image too large (%d > %d bytes)", st.Size(), MaxImageBytes)
	}
	// #nosec G304 -- path is a CLI argument or a name inside that directory
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxImageBytes+1))
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
	return readQRText(img)
}

package crypto

import (
	"strings"

	"github.com/cockroachdb/errors"
)

// Minimal Bech32 (BIP-173) encoder. age encodes X25519 keys as Bech32, but its
// implementation is internal, so we carry an encoder here purely to turn a
// derived 32-byte seed into an "age-secret-key-…" string that age can then
// parse. This is serialization only — no secrets are branched on — and every
// output is cross-checked against age's own decoder in the tests.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

// convertBits regroups bytes from fromBits-wide groups to toBits-wide groups.
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	maxv := byte((1 << toBits) - 1)
	for _, value := range data {
		acc = (acc << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || byte(acc<<(toBits-bits))&maxv != 0 {
		return nil, errors.New("invalid padding in bech32 conversion")
	}
	return out, nil
}

// bech32Encode encodes 8-bit data with the given human-readable prefix.
func bech32Encode(hrp string, data []byte) (string, error) {
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	sum := bech32CreateChecksum(hrp, conv)
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, p := range append(conv, sum...) {
		b.WriteByte(bech32Charset[p])
	}
	return b.String(), nil
}

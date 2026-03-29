package encfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/envutil"
)

// escapeEnvValue escapes a plaintext value for single-line storage.
// Backslashes are doubled (\ → \\) and newlines are encoded as \n.
// This ensures FormatPlaintext → ParsePlaintext roundtrips correctly
// for values that contain embedded newlines (e.g. PEM private keys).
func escapeEnvValue(v string) string {
	if !strings.ContainsAny(v, "\\\n\r") {
		return v // fast path: most values need no escaping
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\r", `\r`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// unescapeEnvValue reverses escapeEnvValue: \\ → \, \n → newline, \r → CR.
func unescapeEnvValue(v string) string {
	if !strings.Contains(v, `\`) {
		return v // fast path
	}
	var sb strings.Builder
	sb.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '\\':
				sb.WriteByte('\\')
				i++
				continue
			case 'n':
				sb.WriteByte('\n')
				i++
				continue
			case 'r':
				sb.WriteByte('\r')
				i++
				continue
			}
		}
		sb.WriteByte(v[i])
	}
	return sb.String()
}

func ParsePlaintext(content string) map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx >= 0 {
			m[line[:idx]] = unescapeEnvValue(line[idx+1:])
		}
	}
	return m
}

func FormatPlaintext(secrets map[string]string) string {
	var buf strings.Builder
	for _, k := range envutil.SortedKeys(secrets) {
		fmt.Fprintf(&buf, "%s=%s\n", k, escapeEnvValue(secrets[k]))
	}
	return buf.String()
}

// LoadSecrets loads secrets either from a plaintext file (if SHH_PLAINTEXT is set)
// or by decrypting the encrypted file.
func LoadSecrets(encFile string, privateKey string) (map[string]string, error) {
	if plainFile := os.Getenv("SHH_PLAINTEXT"); plainFile != "" {
		fmt.Fprintln(os.Stderr, "warning: SHH_PLAINTEXT is set — bypassing encryption and loading secrets from plaintext file")
		data, err := os.ReadFile(plainFile) // #nosec G304 G703 -- SHH_PLAINTEXT is an intentional operator-controlled escape hatch (CI/testing)
		if err != nil {
			return nil, errors.Wrapf(err, "read plaintext file %s", plainFile)
		}
		return ParsePlaintext(string(data)), nil
	}

	ef, err := Load(encFile)
	if err != nil {
		return nil, err
	}
	return DecryptSecrets(ef, privateKey)
}

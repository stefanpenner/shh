package encfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/envutil"
)

func ParsePlaintext(content string) map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx >= 0 {
			m[line[:idx]] = line[idx+1:]
		}
	}
	return m
}

func FormatPlaintext(secrets map[string]string) string {
	var buf strings.Builder
	for _, k := range envutil.SortedKeys(secrets) {
		fmt.Fprintf(&buf, "%s=%s\n", k, secrets[k])
	}
	return buf.String()
}

// LoadSecrets loads secrets either from a plaintext file (if SHH_PLAINTEXT is set)
// or by decrypting the encrypted file.
func LoadSecrets(encFile string, privateKey string) (map[string]string, error) {
	if plainFile := os.Getenv("SHH_PLAINTEXT"); plainFile != "" {
		data, err := os.ReadFile(plainFile)
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

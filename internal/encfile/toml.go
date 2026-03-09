package encfile

import (
	"fmt"

	"github.com/cockroachdb/errors"
)

func tomlKey(s string) string {
	if s == "" {
		return `""`
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return fmt.Sprintf("%q", s)
		}
	}
	return s
}

func validateTOMLValue(s string) error {
	for i, c := range s {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return errors.Newf("value contains control character at position %d (U+%04X)", i, c)
		}
	}
	return nil
}

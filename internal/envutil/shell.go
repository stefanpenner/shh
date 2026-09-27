package envutil

import "strings"

// ShellQuote returns a POSIX single-quoted string safe to use in shell output.
// Single-quoting prevents all shell expansion (variables, backticks, globs).
// The only character that must be handled specially is the single-quote itself,
// which is escaped by ending the single-quoted string, emitting a
// backslash-escaped single-quote, then resuming single-quoting.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func FilterEnv(env []string, remove ...string) []string {
	var kept []string
	for _, entry := range env {
		if listedEnv(entry, remove) {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

func listedEnv(entry string, remove []string) bool {
	for _, name := range remove {
		if strings.HasPrefix(entry, name+"=") {
			return true
		}
	}
	return false
}

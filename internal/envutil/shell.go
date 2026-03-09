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
	var filtered []string
	for _, e := range env {
		skip := false
		for _, r := range remove {
			if strings.HasPrefix(e, r+"=") {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

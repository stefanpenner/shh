package envutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "'hello'"},
		{"empty", "", "''"},
		{"dollar sign", "$HOME", "'$HOME'"},
		{"backtick cmd sub", "`id`", "'`id`'"},
		{"dollar cmd sub", "$(id)", "'$(id)'"},
		{"single quote", "it's", "'it'\\''s'"},
		{"double quote", `say "hi"`, `'say "hi"'`},
		{"newline", "a\nb", "'a\nb'"},
		{"backslash", `a\b`, `'a\b'`},
		{"mixed specials", "$HOME;`id`;$(pwd)", "'$HOME;`id`;$(pwd)'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShellQuote(tt.input))
		})
	}
}

func TestFilterEnv(t *testing.T) {
	env := []string{"FOO=bar", "SHH_AGE_KEY=secret", "BAZ=qux", "OTHER=val"}
	filtered := FilterEnv(env, "SHH_AGE_KEY")

	assert.Len(t, filtered, 3)
	assert.NotContains(t, filtered, "SHH_AGE_KEY=secret")
	assert.Contains(t, filtered, "FOO=bar")
}

func FuzzShellQuote(f *testing.F) {
	f.Add("hello")
	f.Add("it's")
	f.Add("$HOME;`id`")
	f.Add("")
	f.Add("'")
	f.Fuzz(func(t *testing.T, input string) {
		result := ShellQuote(input)
		assert.True(t, strings.HasPrefix(result, "'"))
		assert.True(t, strings.HasSuffix(result, "'"))
	})
}

package envutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvVarKeyValidation(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"FOO", true},
		{"_FOO", true},
		{"FOO_BAR", true},
		{"foo123", true},
		{"123FOO", false},
		{"FOO BAR", false},
		{"FOO=BAR", false},
		{"", false},
		{"FOO-BAR", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.valid, EnvVarKeyPattern.MatchString(tt.key))
		})
	}
}

func TestAgeKeyValidation(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		valid bool
	}{
		{"valid key", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", true},
		{"too short", "age1abc", false},
		{"has comma", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq,q", false},
		{"not age prefix", "notage1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, AgeKeyPattern.MatchString(tt.key))
		})
	}
}

func TestGithubUsernameValidation(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		valid bool
	}{
		{"simple", "alice", true},
		{"with hyphen", "alice-bob", true},
		{"with numbers", "alice123", true},
		{"single char", "a", true},
		{"starts with hyphen", "-alice", false},
		{"ends with hyphen", "alice-", false},
		{"has slash", "alice/bob", false},
		{"empty", "", false},
		{"has space", "alice bob", false},
		{"too long (40 chars)", strings.Repeat("a", 40), false},
		{"max length (39 chars)", strings.Repeat("a", 39), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, GithubUserPattern.MatchString(tt.user))
		})
	}
}

func TestValidateEnvName(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		wantErr bool
	}{
		{"simple", "production", false},
		{"with hyphen", "my-env", false},
		{"with underscore", "my_env", false},
		{"alphanumeric", "env1", false},
		{"path traversal dotdot", "..", true},
		{"path traversal slash", "../etc/passwd", true},
		{"forward slash", "prod/secrets", true},
		{"backslash", `prod\secrets`, true},
		{"leading dot", ".hidden", true},
		{"empty string", "", true},
		{"spaces", "my env", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnvName(tt.envName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDangerousEnvVarDenylist(t *testing.T) {
	blocked := []string{"PATH", "HOME", "SHELL", "USER", "LOGNAME",
		"LD_PRELOAD", "LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"BASH_ENV", "ENV"}
	for _, key := range blocked {
		t.Run(key, func(t *testing.T) {
			assert.True(t, DangerousEnvVars[key], "%s should be in denylist", key)
		})
	}
	assert.False(t, DangerousEnvVars["DATABASE_URL"])
	assert.False(t, DangerousEnvVars["API_KEY"])
}

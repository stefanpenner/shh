package envutil

import "testing"

// SHH_ALLOWED_AGE_PLUGINS is a security boundary (it widens which age plugins may
// be exec'd). A committed secret must never be able to set it, so it must be
// treated as dangerous and never injected from .env.enc into a child process.
func TestSHHAllowedPluginsIsDangerous(t *testing.T) {
	if !DangerousEnvVars["SHH_ALLOWED_AGE_PLUGINS"] {
		t.Fatal("SHH_ALLOWED_AGE_PLUGINS must be in DangerousEnvVars so it can't be set via an injected secret")
	}
}

func TestAdditionalDangerousEnvVars(t *testing.T) {
	for _, key := range []string{"LD_AUDIT", "GIT_SSH_COMMAND", "TAR_OPTIONS"} {
		if !DangerousEnvVars[key] {
			t.Errorf("%s should be blocked as a dangerous environment variable", key)
		}
	}
}

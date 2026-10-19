package github

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	sshtoa "github.com/Mic92/ssh-to-age"
	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/ssh"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
)

var (
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "github.com" {
				return errors.Newf("refusing redirect to %s", req.URL.Host)
			}
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	maxResponseSize int64 = 1 << 20
)

// Username returns the GitHub username from `gh auth status`, or "" if unavailable.
func Username() string {
	out, err := exec.Command("gh", "auth", "status").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if user := ghAccount(line); user != "" {
			return user
		}
	}
	return ""
}

// ghAccount reads "Logged in to github.com account <username>" from one status line.
func ghAccount(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	for i, field := range fields {
		if field != "account" || i+1 >= len(fields) {
			continue
		}
		candidate := strings.TrimRight(fields[i+1], " ()")
		if envutil.GithubUserPattern.MatchString(candidate) {
			return candidate
		}
	}
	return ""
}

func RequireUsername() (string, error) {
	username := Username()
	if username == "" {
		return "", errors.New("GitHub CLI (gh) is required but not installed or not logged in.\n\n  Install: https://cli.github.com\n  Then:    gh auth login")
	}
	return username, nil
}

// ResolvedUser is a resolved recipient. SSHFingerprint is set only when the key
// was fetched from GitHub (the case that needs out-of-band verification).
type ResolvedUser struct {
	AgeKey         string
	Name           string
	SSHFingerprint string
}

// ResolveUserKey resolves the argument to an age public key and a recipient name.
func ResolveUserKey(arg string) (ageKey, name string, err error) {
	info, err := ResolveUser(arg)
	return info.AgeKey, info.Name, err
}

// ResolveUser resolves the argument to a recipient. Age public keys (age1...,
// and tag keys age1tag1... / age1tagpq1...) are accepted directly.
// Everything else is treated as a GitHub username.
func ResolveUser(arg string) (ResolvedUser, error) {
	if envutil.AgeKeyPattern.MatchString(arg) || crypto.IsTagRecipient(arg) {
		return ResolvedUser{AgeKey: arg, Name: arg}, nil
	}
	if !envutil.GithubUserPattern.MatchString(arg) {
		return ResolvedUser{}, errors.Newf("invalid GitHub username or age key: %q", arg)
	}

	fmt.Printf("Fetching SSH keys for github.com/%s...\n", arg)
	ageKey, fp, err := githubAgeKey(arg)
	if err != nil {
		return ResolvedUser{}, err
	}
	fmt.Printf("Converted %s's SSH key -> age key\n", arg)
	return ResolvedUser{AgeKey: ageKey, Name: "https://github.com/" + arg, SSHFingerprint: fp}, nil
}

// githubAgeKey fetches username's ed25519 SSH key and returns the age recipient
// and the SSH SHA256 fingerprint.
func githubAgeKey(username string) (string, string, error) {
	resp, err := httpClient.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return "", "", errors.Wrap(err, "fetch keys")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.Newf("could not fetch keys for %q (HTTP %d)", username, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", "", err
	}

	line := ed25519Line(string(body))
	if line == "" {
		return "", "", errors.Newf("no ed25519 SSH key found for %q (age requires ed25519)", username)
	}
	return ageFromSSHLine(line)
}

func ageFromSSHLine(line string) (string, string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", "", errors.Wrap(err, "parse ssh key")
	}
	ageKey, err := sshtoa.SSHPublicKeyToAge([]byte(line))
	if err != nil {
		return "", "", errors.Wrap(err, "ssh-to-age")
	}
	return *ageKey, ssh.FingerprintSHA256(pub), nil
}

func ed25519Line(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "ssh-ed25519") {
			return line
		}
	}
	return ""
}

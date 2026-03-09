package template

import (
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
)

var Pattern = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}`)

func Render(tmpl string, secrets map[string]string) (string, error) {
	var missing []string
	result := Pattern.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := Pattern.FindStringSubmatch(match)[1]
		val, ok := secrets[key]
		if !ok {
			missing = append(missing, key)
			return match
		}
		return val
	})
	if len(missing) > 0 {
		return "", errors.Newf("unresolved placeholders: %s", strings.Join(missing, ", "))
	}
	return result, nil
}

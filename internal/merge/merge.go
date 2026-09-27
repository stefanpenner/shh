package merge

import (
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
)

func MergeSecrets(ancestor, ours, theirs map[string]string) (map[string]string, []string, error) {
	allKeys := make(map[string]bool)
	for k := range ancestor {
		allKeys[k] = true
	}
	for k := range ours {
		allKeys[k] = true
	}
	for k := range theirs {
		allKeys[k] = true
	}

	result := make(map[string]string)
	var conflicts []string

	for k := range allKeys {
		aVal, aOK := ancestor[k]
		oVal, oOK := ours[k]
		tVal, tOK := theirs[k]

		switch {
		case oOK && tOK && oVal == tVal:
			result[k] = oVal
		case !oOK && !tOK:
			continue
		case oOK && !tOK && !aOK:
			result[k] = oVal
		case !oOK && tOK && !aOK:
			result[k] = tVal
		case oOK && !tOK && aOK:
			if oVal != aVal {
				conflicts = append(conflicts, k)
			}
		case !oOK && tOK && aOK:
			if tVal != aVal {
				conflicts = append(conflicts, k)
			}
		case oOK && tOK && aOK:
			if oVal == aVal {
				result[k] = tVal
			} else if tVal == aVal {
				result[k] = oVal
			} else {
				conflicts = append(conflicts, k)
			}
		case oOK && tOK && !aOK:
			conflicts = append(conflicts, k)
		default:
			conflicts = append(conflicts, k)
		}
	}

	sort.Strings(conflicts)
	if len(conflicts) > 0 {
		return nil, conflicts, errors.Newf("merge conflict on keys: %s", strings.Join(conflicts, ", "))
	}
	return result, nil, nil
}

func MergeStringMaps(ancestor, ours, theirs map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range ours {
		result[k] = v
	}
	for k, v := range theirs {
		if _, ok := result[k]; !ok {
			result[k] = v
		}
	}
	for k := range ancestor {
		_, inOurs := ours[k]
		_, inTheirs := theirs[k]
		if !inOurs || !inTheirs {
			delete(result, k)
		}
	}
	return result
}

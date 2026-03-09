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
			// both agree
			result[k] = oVal
		case !oOK && !tOK:
			// both deleted
		case oOK && !tOK && !aOK:
			// added only in ours
			result[k] = oVal
		case !oOK && tOK && !aOK:
			// added only in theirs
			result[k] = tVal
		case oOK && !tOK && aOK:
			// theirs deleted
			if oVal == aVal {
				// ours unchanged, accept deletion
			} else {
				conflicts = append(conflicts, k)
			}
		case !oOK && tOK && aOK:
			// ours deleted
			if tVal == aVal {
				// theirs unchanged, accept deletion
			} else {
				conflicts = append(conflicts, k)
			}
		case oOK && tOK && aOK:
			if oVal == aVal {
				// only theirs changed
				result[k] = tVal
			} else if tVal == aVal {
				// only ours changed
				result[k] = oVal
			} else {
				// both changed differently
				conflicts = append(conflicts, k)
			}
		case oOK && tOK && !aOK:
			// both added with different values
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
	// Union of ours and theirs; if both added/kept, prefer ours
	for k, v := range ours {
		result[k] = v
	}
	for k, v := range theirs {
		if _, ok := result[k]; !ok {
			result[k] = v
		}
	}
	// Handle deletions: if ancestor had it and one side removed it, remove it
	for k := range ancestor {
		_, inOurs := ours[k]
		_, inTheirs := theirs[k]
		if !inOurs || !inTheirs {
			delete(result, k)
		}
	}
	return result
}

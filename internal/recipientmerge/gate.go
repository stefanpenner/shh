package recipientmerge

import "errors"

// ErrSetsDiffer means ours and theirs do not list the same recipients.
var ErrSetsDiffer = errors.New("recipient sets differ. Refusing the merge. Change recipients with shh users")

// Decide runs one merge attempt from Init.
// equal is the observation that both sides list the same recipients.
// The actions come from the generated spec. This function does not restate the guard.
func Decide(equal bool) (State, []TraceEntry, error) {
	s := Init()
	var tr []TraceEntry
	if equal {
		if !s.CanNoteEqual() {
			return s, tr, errors.New("note-equal is disabled")
		}
		var e TraceEntry
		e, s = s.Trace("NoteEqual")
		tr = append(tr, e)
	}
	if !s.CanMerge() {
		return s, tr, ErrSetsDiffer
	}
	e, s := s.Trace("Merge")
	tr = append(tr, e)
	return s, tr, nil
}

package vaultadmit

import "errors"

// ErrUnreviewed means the recipient set is not the HEAD set and the operator did not accept it.
var ErrUnreviewed = errors.New("recipient set differs from HEAD. Review shh users list. Pass --accept-recipients to write")

// Decide runs one write attempt from Init.
// differs is the observation that the recipient set is not the HEAD set.
// accept is the operator flag.
// The actions come from the generated spec. This function does not restate the guard.
func Decide(differs, accept bool) (State, []TraceEntry, error) {
	s := Init()
	var tr []TraceEntry
	if differs {
		if !s.CanForge() {
			return s, tr, errors.New("forge is disabled")
		}
		var e TraceEntry
		e, s = s.Trace("Forge")
		tr = append(tr, e)
	}
	if accept && s.CanAccept() {
		var e TraceEntry
		e, s = s.Trace("Accept")
		tr = append(tr, e)
	}
	if !s.CanSet() {
		return s, tr, ErrUnreviewed
	}
	e, s := s.Trace("Set")
	tr = append(tr, e)
	return s, tr, nil
}

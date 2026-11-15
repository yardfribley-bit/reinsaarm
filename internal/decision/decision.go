// Package decision lists the five AARM authorization decisions (R4).
package decision

// Decision is one AARM authorization result.
type Decision string

const (
	Allow  Decision = "ALLOW"
	Deny   Decision = "DENY"
	Modify Decision = "MODIFY"
	StepUp Decision = "STEP_UP"
	Defer  Decision = "DEFER"
	// Gray is internal. It is not an AARM decision. The daemon resolves it
	// through the judge or the fail mode before a receipt is written.
	Gray Decision = "GRAY"
	// Observe is a sensor evidence event, not an authorization decision.
	Observe Decision = "OBSERVE"
)

// Rank orders decisions so a stricter result wins. Gray and Observe are not
// stricter than an explicit authorization.
func Rank(d Decision) int {
	switch d {
	case Deny:
		return 50
	case Defer:
		return 40
	case StepUp:
		return 30
	case Modify:
		return 20
	case Gray:
		return 10
	case Allow:
		return 0
	default:
		return -1
	}
}

// IsFive reports whether d is one of the five AARM decisions.
func IsFive(d Decision) bool {
	switch d {
	case Allow, Deny, Modify, StepUp, Defer:
		return true
	default:
		return false
	}
}

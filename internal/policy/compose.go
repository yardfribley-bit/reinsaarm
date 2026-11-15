package policy

import (
	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/judge"
)

// Composed is the decision after mode, fail policy, and an optional judge.
type Composed struct {
	Decision decision.Decision
	Enforced decision.Decision
	Tier     string
	RuleIDs  []string
	Reason   string
	Rewrite  string
	Verdict  string
	Degraded bool
	Shadow   bool
}

// Compose applies AARM decision synthesis.
// An explicit T0 DENY is final. Gray zones may call a judge verdict that the
// caller already obtained. mode is audit, review, or enforce.
func Compose(t0 Outcome, v *judge.Verdict, judgeErr error, mode, failMode string, unattended bool, minConfidence float64) Composed {
	c := Composed{
		Decision: t0.Decision,
		Enforced: t0.Decision,
		Tier:     "T0",
		RuleIDs:  append([]string{}, t0.RuleIDs...),
		Reason:   t0.Reason,
		Rewrite:  t0.Rewrite,
	}
	if t0.Decision == decision.Deny {
		c = applyMode(c, mode, unattended, true)
		return c
	}
	if t0.Decision == decision.Gray {
		c = resolveGray(c, t0, v, judgeErr, failMode, minConfidence)
	}
	explicitDeny := false
	for _, h := range t0.Hits {
		if h.Decision == decision.Deny {
			explicitDeny = true
		}
	}
	return applyMode(c, mode, unattended, explicitDeny)
}

func resolveGray(c Composed, t0 Outcome, v *judge.Verdict, judgeErr error, failMode string, minConfidence float64) Composed {
	c.Tier = "T2"
	if v == nil || judgeErr != nil || v.Verdict == "" {
		c.Degraded = true
		c.Verdict = "uncertain"
		if judgeErr != nil {
			c.Reason = "judge unavailable; " + t0.Reason
		} else if v != nil && v.Verdict == "uncertain" {
			c.Reason = "judge uncertain; " + t0.Reason
			if len(v.Reasons) > 0 {
				c.Reason = c.Reason + "; " + v.Reasons[0]
			}
		} else {
			c.Reason = "judge disabled; " + t0.Reason
			c.Tier = "T0"
		}
		if failMode == "open" {
			c.Decision = decision.Allow
			c.Enforced = decision.Allow
			return c
		}
		if t0.Risk == "read" {
			c.Decision = decision.Defer
		} else {
			c.Decision = decision.StepUp
		}
		c.Enforced = c.Decision
		return c
	}
	c.Verdict = v.Verdict
	if len(v.Reasons) > 0 {
		c.Reason = v.Reasons[0]
	}
	switch v.Verdict {
	case "malicious":
		if v.Confidence >= minConfidence {
			c.Decision = decision.Deny
		} else {
			c.Decision = decision.StepUp
		}
	case "out_of_remit":
		c.Decision = decision.StepUp
	case "benign":
		c.Decision = decision.Allow
	default:
		c.Decision = decision.StepUp
		c.Verdict = "uncertain"
	}
	c.Enforced = c.Decision
	return c
}

func applyMode(c Composed, mode string, unattended bool, explicitDeny bool) Composed {
	c.Enforced = c.Decision
	switch mode {
	case "audit":
		if c.Decision != decision.Allow {
			c.Shadow = true
			c.Enforced = decision.Allow
		}
	case "review":
		if c.Decision == decision.Deny && !explicitDeny {
			c.Decision = decision.StepUp
			c.Enforced = decision.StepUp
			c.Reason = "review mode holds judge denials for approval; " + c.Reason
		}
	}
	if unattended && (c.Enforced == decision.StepUp || c.Enforced == decision.Defer) {
		c.Enforced = decision.Deny
		c.Reason = "unattended runner denies approval and defer; " + c.Reason
	}
	return c
}

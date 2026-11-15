package config

import "testing"

func TestCaptureLimits(t *testing.T) {
	var c Capture
	a, o, m, links, tr := c.Limits()
	if a != 600 || o != 800 || m != 2000 || !links || !tr {
		t.Fatalf("defaults %d %d %d %v %v", a, o, m, links, tr)
	}
	c.Off = true
	if a, o, m, links, tr = c.Limits(); a != 0 || links || tr || o >= 800 || m >= 2000 {
		t.Fatalf("off %d %d %d %v %v", a, o, m, links, tr)
	}
}

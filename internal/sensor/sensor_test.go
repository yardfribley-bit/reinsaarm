package sensor

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestScanSeesForeignFD(t *testing.T) {
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no /proc")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", "exec 3<> \"$1\"; sleep 30", "bash", target)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(2 * time.Second)
	var found bool
	for time.Now().Before(deadline) {
		for _, f := range Scan([]string{target}) {
			if f.Path == target && f.PID == cmd.Process.Pid {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !found {
		t.Fatal("sensor did not see the credential fd")
	}
}

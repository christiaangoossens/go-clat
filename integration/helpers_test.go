package integration

import (
	"os"
	"strings"
	"testing"
	"time"
)

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// waitFor polls until done returns true, for at most five seconds.
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); !done(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// readSysctl returns a sysctl of the network namespace of the calling thread.
func readSysctl(t *testing.T, name string) string {
	t.Helper()

	value, err := os.ReadFile("/proc/sys/" + name)
	must(t, err)

	return strings.TrimSpace(string(value))
}

// setSysctl sets a sysctl of the network namespace of the calling thread.
func setSysctl(name, value string) error {
	return os.WriteFile("/proc/sys/"+name, []byte(value), 0o644)
}

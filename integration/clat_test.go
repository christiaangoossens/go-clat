package integration

import (
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// clatProcess is a running go-clat binary.
type clatProcess struct {
	cmd     *exec.Cmd
	log     *processLog
	done    chan struct{} // closed when go-clat has exited
	waitErr error         // why go-clat exited, set before done is closed
}

// startCLAT starts go-clat with the given NAT64 prefix and waits until it has added its ip6tables rules, the last thing it
// sets up before it translates. Its log is shown when the test fails.
func startCLAT(t *testing.T, prefix string) *clatProcess {
	t.Helper()

	clat := &clatProcess{
		cmd:  exec.Command(*clatBinary, "-nat64-prefix", prefix), // DNS64 discovery would time out here
		log:  &processLog{},
		done: make(chan struct{}),
	}
	clat.cmd.Stdout = clat.log
	clat.cmd.Stderr = clat.log

	// Kill go-clat if the test binary dies. The signal comes when the thread that started go-clat exits, so keep this
	// test on its thread until it ends.
	clat.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)

	if err := clat.cmd.Start(); err != nil {
		t.Fatalf("starting go-clat: %v", err)
	}

	go func() {
		clat.waitErr = clat.cmd.Wait()
		close(clat.done)
	}()

	t.Cleanup(func() {
		clat.cmd.Process.Kill()
		<-clat.done

		if t.Failed() {
			t.Logf("go-clat log:\n%s", clat.log)
		}
	})

	waitFor(t, "go-clat to add its ip6tables rules", func() bool {
		select {
		case <-clat.done:
			t.Fatalf("go-clat exited before it was ready: %v", clat.waitErr)
		default:
		}

		return len(clatRules(t)) == len(wantedRules)
	})

	return clat
}

// stop sends SIGTERM and waits for go-clat to exit cleanly.
func (c *clatProcess) stop(t *testing.T) {
	t.Helper()

	must(t, c.cmd.Process.Signal(syscall.SIGTERM))

	select {
	case <-c.done:
		if c.waitErr != nil {
			t.Fatalf("go-clat did not exit cleanly: %v", c.waitErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("go-clat did not exit within 5 seconds")
	}
}

// The addresses go-clat gives its IPv4 tun, and the network of its IPv6 tun.
var (
	clatIPv4TunAddr = net.IPv4(192, 0, 0, 1)
	clatIPv6TunNet  = mustParseAddr("fdb1:5394:aa52:6464:6464::/64")
)

// clatTuns returns the names of go-clat's IPv4 and IPv6 tuns, found by their addresses.
func clatTuns(t *testing.T) (ipv4Tun, ipv6Tun string) {
	t.Helper()

	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	must(t, err)

	for _, addr := range addrs {
		link, err := netlink.LinkByIndex(addr.LinkIndex)
		must(t, err)

		switch {
		case addr.IP.Equal(clatIPv4TunAddr):
			ipv4Tun = link.Attrs().Name
		case clatIPv6TunNet.Contains(addr.IP):
			ipv6Tun = link.Attrs().Name
		}
	}

	if ipv4Tun == "" || ipv6Tun == "" {
		t.Fatalf("go-clat's tuns not found: IPv4 %q, IPv6 %q", ipv4Tun, ipv6Tun)
	}

	return ipv4Tun, ipv6Tun
}

// processLog collects go-clat's output, which comes from two goroutines (stdout and stderr).
type processLog struct {
	mu     sync.Mutex
	output bytes.Buffer
}

func (l *processLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.output.Write(p)
}

func (l *processLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.output.String()
}

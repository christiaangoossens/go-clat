// Package integration runs the real go-clat binary in a sandbox without IPv4 and checks that IPv4 traffic gets through.
//
// Run it from the repository root with:
//
//	go -C integration test -count=1 ./...
//
// The test binary re-runs itself in a new user and network namespace, so it needs no root and never touches the
// host's network. -count=1 is needed because the Go test cache does not see changes to go-clat itself.
//
// A user namespace cannot load kernel modules, so go-clat's SNAT rule needs the host's IPv6 NAT support (ip6table_nat
// or nf_tables NAT) to be loaded already.
package integration

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// clatBinary is set only inside the sandbox, by the test binary that started it.
var clatBinary = flag.String("clat-binary", "", "internal: path to the go-clat binary; marks that we run in the sandbox")

func TestMain(m *testing.M) {
	flag.Parse()

	if *clatBinary == "" {
		os.Exit(runInSandbox())
	}

	if err := checkSandbox(); err != nil {
		log.Fatalf("refusing to run: %v", err)
	}

	os.Exit(m.Run())
}

// runInSandbox builds go-clat and runs this test binary again in a new user and network namespace, mapped to root.
func runInSandbox() int {
	dir, err := os.MkdirTemp("", "go-clat-integration-")
	if err != nil {
		log.Print(err)
		return 1
	}
	defer os.RemoveAll(dir)

	binary := filepath.Join(dir, "go-clat")
	if err := buildCLAT(binary); err != nil {
		log.Print(err)
		return 1
	}

	// The flag goes first: flag parsing stops at the first argument that is not a flag.
	cmd := exec.Command(os.Args[0], append([]string{"-clat-binary=" + binary}, os.Args[1:]...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH")+":/usr/sbin:/sbin",           // ip6tables
		"XTABLES_LOCKFILE="+filepath.Join(dir, "xtables.lock"), // not the host's /run/xtables.lock
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}

	err = cmd.Run()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}

	if err != nil {
		log.Printf("starting the sandbox: %v (are unprivileged user namespaces allowed?)", err)
		return 1
	}

	return 0
}

// buildCLAT builds go-clat from the repository root, which is a different module than this one.
func buildCLAT(output string) error {
	cmd := exec.Command("go", "build", "-o", output, ".")
	cmd.Dir = ".."
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("building go-clat: %w", err)
	}

	return nil
}

// checkSandbox makes sure we are in a new user namespace and a fresh network namespace before changing anything.
func checkSandbox() error {
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}

	if strings.Join(strings.Fields(string(uidMap)), " ") == "0 0 4294967295" {
		return errors.New("not inside a user namespace")
	}

	links, err := netlink.LinkList()
	if err != nil {
		return err
	}

	// Every link in a new network namespace is down, even lo. It can have more links than lo, such as sit0.
	for _, link := range links {
		if link.Attrs().Flags&net.FlagUp != 0 {
			return fmt.Errorf("this network namespace is not fresh: %s is up", link.Attrs().Name)
		}
	}

	return nil
}

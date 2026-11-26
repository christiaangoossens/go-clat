package integration

import (
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// testNoIPv4 checks that the CLAT host cannot reach 1.1.1.1 on its own, so IPv4 can only work through go-clat. This is
// what a user sees: "Network is unreachable".
func testNoIPv4(t *testing.T) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remoteIPv4, Port: echoPort})
	if err == nil {
		conn.Close()
	}

	if !errors.Is(err, unix.ENETUNREACH) {
		t.Errorf("connecting to %s: %v, want ENETUNREACH", remoteIPv4, err)
	}
}

// The settings go-clat changes while it runs, with their values in a new network namespace.
var restoredSysctls = map[string]string{
	"net/ipv6/conf/all/forwarding":               "0",
	"net/ipv6/conf/lo/forwarding":                "1",
	"net/ipv6/conf/default/accept_ra":            "1",
	"net/ipv6/conf/" + clatUplink + "/accept_ra": "1",
}

// testShutdown checks that go-clat undoes its changes: its public IPv6 address, the SNAT rule, and the forwarding
// settings.
func testShutdown(t *testing.T, clat *clatProcess) {
	addrs, rules := publicAddrs(t), clatRules(t)
	if len(addrs) != 1 || len(rules) != len(wantedRules) {
		t.Fatalf("while running, want one public address and the rules %v, got %v and %v", wantedRules, addrs, rules)
	}

	if forwarding := readSysctl(t, "net/ipv6/conf/all/forwarding"); forwarding != "1" {
		t.Fatalf("while running, want IPv6 forwarding enabled, got %s", forwarding)
	}

	if acceptRA := readSysctl(t, "net/ipv6/conf/lo/accept_ra"); acceptRA != "1" {
		t.Errorf("while running, lo already forwarded, so its accept_ra should stay 1, got %s", acceptRA)
	}

	clat.stop(t)

	if addrs := publicAddrs(t); len(addrs) > 0 {
		t.Errorf("public address %v is still on %s", addrs, clatUplink)
	}

	if rules := clatRules(t); len(rules) > 0 {
		t.Errorf("ip6tables rules are still there: %v", rules)
	}

	for name, want := range restoredSysctls {
		if got := readSysctl(t, name); got != want {
			t.Errorf("%s is %s after shutdown, want %s", name, got, want)
		}
	}

	testNoIPv4(t)
}

// publicAddrs returns the global addresses go-clat added to the uplink.
func publicAddrs(t *testing.T) []netlink.Addr {
	t.Helper()

	var added []netlink.Addr
	for _, addr := range uplinkGlobalAddrs(t) {
		if !hostAddrs[addr.IP.String()] {
			added = append(added, addr)
		}
	}

	return added
}

// wantedRules are the kinds of ip6tables rules go-clat adds: an SNAT rule, and two FORWARD accepts for its replies and
// its own ICMP errors, as table, chain and target.
var wantedRules = [][3]string{
	{"nat", "POSTROUTING", "-j SNAT"},
	{"filter", "FORWARD", "-j ACCEPT"},
	{"filter", "FORWARD", "-j ACCEPT"},
}

// clatRules returns the ip6tables rules go-clat added. The sandbox has no rules of its own in these chains.
func clatRules(t *testing.T) []string {
	t.Helper()

	var rules []string
	for _, chain := range [][2]string{{"nat", "POSTROUTING"}, {"filter", "FORWARD"}} {
		output, err := exec.Command("ip6tables", "-t", chain[0], "-S", chain[1]).Output()
		must(t, err)

		for _, rule := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(rule, "-A ") {
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

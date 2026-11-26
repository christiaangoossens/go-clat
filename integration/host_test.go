package integration

import (
	"os/exec"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The CLAT host is set up like a real IPv6-only machine, not just with what the tests need:
//   - lo keeps 127.0.0.1, as on every real host;
//   - an interface with a global prefix of its own (like a VPN) comes before the uplink;
//   - the uplink gets its addresses from SLAAC, with privacy addresses and duplicate address detection;
//   - next to them, a DHCPv6 address (/128) and a deprecated address from an earlier prefix of the network;
//   - lo already forwards IPv6, to check that go-clat leaves it alone and restores it;
//   - the firewall drops forwarded IPv6, as Docker's does.
var (
	vpnAddr        = mustParseAddr("2001:db8:99::1/64")
	dhcpv6Addr     = mustParseAddr("2001:db8:1::1:100/128")
	deprecatedAddr = mustParseAddr("2001:db8:0:1::2/64")
)

const vpnLink = "vpn0"

// hostAddrs are the uplink's addresses before go-clat runs, to tell them apart from the address go-clat adds.
var hostAddrs = map[string]bool{}

// setupHostBeforeUplink brings lo up and creates the VPN interface, so it comes before the uplink.
func setupHostBeforeUplink(t *testing.T, clatHandle *netlink.Handle) {
	t.Helper()

	must(t, clatHandle.LinkSetUp(linkByName(t, clatHandle, "lo")))
	must(t, setSysctl("net/ipv6/conf/lo/forwarding", "1"))

	// A veth pair stands in for the VPN's tunnel: it needs no extra kernel module.
	vpn := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: vpnLink}, PeerName: vpnLink + "-remote"}
	must(t, clatHandle.LinkAdd(vpn))
	must(t, clatHandle.AddrAdd(linkByName(t, clatHandle, vpnLink), withoutDAD(vpnAddr)))
	must(t, clatHandle.LinkSetUp(linkByName(t, clatHandle, vpnLink)))
	must(t, clatHandle.LinkSetUp(linkByName(t, clatHandle, vpnLink+"-remote")))

	output, err := exec.Command("ip6tables", "-P", "FORWARD", "DROP").CombinedOutput()
	if err != nil {
		t.Fatalf("setting the FORWARD policy: %v: %s", err, output)
	}
}

// setupHostUplink enables privacy addresses on the uplink, and adds the DHCPv6 and deprecated addresses.
func setupHostUplink(t *testing.T, clatHandle *netlink.Handle) {
	t.Helper()

	must(t, setSysctl("net/ipv6/conf/"+clatUplink+"/use_tempaddr", "2"))

	uplink := linkByName(t, clatHandle, clatUplink)
	must(t, clatHandle.LinkSetUp(uplink))
	must(t, clatHandle.AddrAdd(uplink, dhcpv6Addr))

	deprecated := *deprecatedAddr
	deprecated.ValidLft = int(time.Hour / time.Second)
	deprecated.PreferedLft = 0
	must(t, clatHandle.AddrAdd(uplink, &deprecated))
}

// waitForSLAAC waits until the uplink has its SLAAC address and privacy address, both past duplicate address
// detection.
func waitForSLAAC(t *testing.T, clatHandle *netlink.Handle) {
	t.Helper()

	waitFor(t, "SLAAC and privacy addresses", func() bool {
		addrs, err := clatHandle.AddrList(linkByName(t, clatHandle, clatUplink), netlink.FAMILY_V6)
		must(t, err)

		var slaac, privacy bool
		for _, addr := range addrs {
			ones, _ := addr.Mask.Size()
			usable := addr.Flags&unix.IFA_F_TENTATIVE == 0
			if !usable || ones != 64 || !advertisedPrefix.Contains(addr.IP) {
				continue
			}

			if addr.Flags&unix.IFA_F_TEMPORARY != 0 {
				privacy = true
			} else {
				slaac = true
			}
		}

		return slaac && privacy
	})
}

func rememberHostAddrs(t *testing.T) {
	t.Helper()

	for _, addr := range uplinkGlobalAddrs(t) {
		hostAddrs[addr.IP.String()] = true
	}
}

func uplinkGlobalAddrs(t *testing.T) []netlink.Addr {
	t.Helper()

	uplink, err := netlink.LinkByName(clatUplink)
	must(t, err)

	addrs, err := netlink.AddrList(uplink, netlink.FAMILY_V6)
	must(t, err)

	var global []netlink.Addr
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			global = append(global, addr)
		}
	}

	return global
}

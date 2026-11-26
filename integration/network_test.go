package integration

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The test network. The test process itself is the CLAT host; the peer namespace is its router and the internet
// behind a NAT64. The CLAT host gets its address and default route from the router's advertisements (SLAAC).
//
//	[ CLAT namespace ]                       [ peer namespace ]
//	go-clat, IPv4 tests                      the router and the "internet"
//	vclat 2001:db8:1::/64 (SLAAC) <= veth => vpeer 2001:db8:1::1/64
//	                                         lo    64:ff9b::101:101 (1.1.1.1 behind the NAT64 prefix)
var (
	peerUplinkAddr = mustParseAddr("2001:db8:1::1/64")
	remoteAddr     = mustParseAddr("64:ff9b::101:101/128")

	// remoteIPv4 is how the CLAT host reaches remoteAddr: its last 32 bits.
	remoteIPv4 = net.IPv4(1, 1, 1, 1)
)

const (
	clatUplink  = "vclat"
	peerUplink  = "vpeer"
	nat64Prefix = "64:ff9b::/96"
)

// setupNetwork builds the test network and returns the peer namespace. The CLAT host is set up like a real one, see
// setupHost.
//
// The CLAT namespace is the one this process runs in, so the network can be set up only once per process.
func setupNetwork(t *testing.T) netns.NsHandle {
	t.Helper()

	peer, err := newNetns()
	if err != nil {
		t.Fatalf("creating the peer namespace: %v", err)
	}
	t.Cleanup(func() { peer.Close() })

	clatHandle, err := netlink.NewHandle()
	must(t, err)
	defer clatHandle.Close()

	peerHandle, err := netlink.NewHandleAt(peer)
	must(t, err)
	defer peerHandle.Close()

	// The router's state is not under test: skip its duplicate address detection, so it can advertise at once.
	must(t, inNetns(peer, func() error { return setSysctl("net/ipv6/conf/default/accept_dad", "0") }))

	setupHostBeforeUplink(t, clatHandle)
	setupUplink(t, clatHandle, peer)
	setupHostUplink(t, clatHandle)
	setupPeer(t, peerHandle)

	// The peer is a router, so its Neighbor Advertisements carry the Router flag. Without it, the CLAT host concludes
	// that the router became a host and drops the default route through it (RFC 4861 Section 7.2.5).
	must(t, inNetns(peer, func() error { return setSysctl("net/ipv6/conf/all/forwarding", "1") }))
	advertiseRouter(t, peer)

	waitFor(t, "a default route from the router's advertisements", func() bool { return hasDefaultRoute(t) })
	waitForSLAAC(t, clatHandle)
	rememberHostAddrs(t)

	return peer
}

// setupUplink creates the veth pair and moves one end into the peer namespace.
func setupUplink(t *testing.T, clatHandle *netlink.Handle, peer netns.NsHandle) {
	t.Helper()

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: clatUplink}, PeerName: peerUplink}
	must(t, clatHandle.LinkAdd(veth))
	must(t, clatHandle.LinkSetNsFd(linkByName(t, clatHandle, peerUplink), int(peer)))
}

// setupPeer gives the peer its uplink address and puts the remote host on its lo.
func setupPeer(t *testing.T, peerHandle *netlink.Handle) {
	t.Helper()

	lo := linkByName(t, peerHandle, "lo")
	must(t, peerHandle.LinkSetUp(lo))

	for _, remote := range remoteAddrs() {
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: remote, Mask: net.CIDRMask(128, 128)}}
		must(t, peerHandle.AddrAdd(lo, addr))
	}

	uplink := linkByName(t, peerHandle, peerUplink)
	must(t, peerHandle.AddrAdd(uplink, withoutDAD(peerUplinkAddr)))
	must(t, peerHandle.LinkSetUp(uplink))
}

func linkByName(t *testing.T, handle *netlink.Handle, name string) netlink.Link {
	t.Helper()

	link, err := handle.LinkByName(name)
	if err != nil {
		t.Fatalf("finding link %s: %v", name, err)
	}

	return link
}

func withoutDAD(addr *netlink.Addr) *netlink.Addr {
	withFlags := *addr
	withFlags.Flags = unix.IFA_F_NODAD

	return &withFlags
}

func mustParseAddr(cidr string) *netlink.Addr {
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		panic(err)
	}

	return addr
}

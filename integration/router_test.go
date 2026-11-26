package integration

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// The peer is the uplink's router and advertises itself as the default router, like a real network with SLAAC. The
// short lifetime makes a CLAT host that stops accepting the advertisements lose its default route within seconds.
const (
	routerLifetime           = 3 * time.Second
	routerAdvertisementEvery = 250 * time.Millisecond
)

// advertisedPrefix is the uplink's prefix, which the CLAT host uses for SLAAC.
var advertisedPrefix = mustParseAddr("2001:db8:1::/64")

// advertiseRouter makes the peer send Router Advertisements on its uplink until the test ends.
func advertiseRouter(t *testing.T, peer netns.NsHandle) {
	t.Helper()

	var conn *icmp.PacketConn
	var uplink *net.Interface

	err := inNetns(peer, func() (err error) {
		if uplink, err = net.InterfaceByName(peerUplink); err != nil {
			return err
		}

		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		return err
	})
	must(t, err)

	// RFC 4861 Section 6.1.2: a host ignores advertisements that did not come from a neighbor (hop limit 255).
	must(t, conn.IPv6PacketConn().SetMulticastHopLimit(255))
	must(t, conn.IPv6PacketConn().SetMulticastInterface(uplink))

	message := icmp.Message{Type: ipv6.ICMPTypeRouterAdvertisement, Body: &icmp.RawBody{Data: routerAdvertisement()}}
	packet, err := message.Marshal(nil) // the kernel computes the checksum
	must(t, err)

	allNodes := &net.IPAddr{IP: net.IPv6linklocalallnodes, Zone: strconv.Itoa(uplink.Index)}
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(routerAdvertisementEvery)
		defer ticker.Stop()

		for {
			conn.WriteTo(packet, allNodes)

			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()

	t.Cleanup(func() {
		close(stop)
		conn.Close()
	})
}

// routerAdvertisement returns the body of a Router Advertisement (RFC 4861 Section 4.2) that makes the peer the
// default router and advertises the uplink's prefix for SLAAC.
func routerAdvertisement() []byte {
	body := make([]byte, 12+32) // the advertisement itself, then a Prefix Information option
	binary.BigEndian.PutUint16(body[2:], uint16(routerLifetime/time.Second))

	// RFC 4861 Section 4.6.2: on-link and autonomous (SLAAC), with the lifetimes of a typical home router.
	prefix := body[12:]
	ones, _ := advertisedPrefix.Mask.Size()
	prefix[0], prefix[1], prefix[2], prefix[3] = 3, 4, byte(ones), 0xc0      // type, length in 8 bytes, prefix length, L+A
	binary.BigEndian.PutUint32(prefix[4:], uint32(24*time.Hour/time.Second)) // valid lifetime
	binary.BigEndian.PutUint32(prefix[8:], uint32(4*time.Hour/time.Second))  // preferred lifetime
	copy(prefix[16:], advertisedPrefix.IP.To16())

	return body
}

// testRouterAdvertisementsAccepted checks that the CLAT host still accepts Router Advertisements while go-clat runs.
// Linux ignores them on interfaces with forwarding enabled, and removes the default routes they gave when forwarding
// is enabled. The route list still shows an expired route for a while, so only the echo proves that the route was
// refreshed after its lifetime.
func testRouterAdvertisementsAccepted(t *testing.T) {
	time.Sleep(routerLifetime + time.Second)

	if !hasDefaultRoute(t) {
		t.Fatal("the default route from the router's advertisements is gone")
	}

	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: remoteAddr.IP, Port: echoPort})
	must(t, err)
	defer conn.Close()

	expectEcho(t, conn, []byte("plain IPv6 still works"))
}

// hasDefaultRoute reports whether the CLAT host has a default IPv6 route over its uplink from Router Advertisements.
func hasDefaultRoute(t *testing.T) bool {
	t.Helper()

	uplink, err := netlink.LinkByName(clatUplink)
	must(t, err)

	routes, err := netlink.RouteList(uplink, netlink.FAMILY_V6)
	must(t, err)

	for _, route := range routes {
		isDefault := route.Dst == nil || route.Dst.IP.IsUnspecified()
		if isDefault && route.Protocol == unix.RTPROT_RA {
			return true
		}
	}

	return false
}

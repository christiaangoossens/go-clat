package integration

import (
	"net"
	"testing"
)

// Network-specific NAT64 prefixes, as an operator may use instead of the well-known 64:ff9b::/96, with the address of
// 1.1.1.1 in each (RFC 6052 Section 2.2). Unlike the well-known prefix, they are not checksum-neutral, and in a /48
// the IPv4 address is split around the u-octet (bits 64 to 71, always zero).
var networkSpecificPrefixes = []struct {
	prefix string
	remote string
}{
	{prefix: "2001:db8:64::/96", remote: "2001:db8:64::101:101"},
	{prefix: "64:ff9b:1::/48", remote: "64:ff9b:1:101:1:100::"},
}

// remoteAddrs returns the remote host's addresses: 1.1.1.1 in the well-known and each network-specific prefix.
func remoteAddrs() []net.IP {
	addrs := []net.IP{remoteAddr.IP}
	for _, nsp := range networkSpecificPrefixes {
		addrs = append(addrs, net.ParseIP(nsp.remote))
	}

	return addrs
}

// testNetworkSpecificPrefixes restarts go-clat with each network-specific prefix and checks that traffic gets through.
func testNetworkSpecificPrefixes(t *testing.T) {
	for _, nsp := range networkSpecificPrefixes {
		t.Run(nsp.prefix, func(t *testing.T) {
			clat := startCLAT(t, nsp.prefix)

			t.Run("ping", testPing)
			t.Run("UDP echo", testUDPEcho)
			t.Run("HTTP download of 1 MB", testHTTPDownload)

			clat.stop(t)
		})
	}
}

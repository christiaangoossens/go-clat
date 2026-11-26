package main

import (
	"net"
	"testing"
)

func candidate(t *testing.T, cidr, iface string) ipv6Candidate {
	t.Helper()

	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}

	return ipv6Candidate{prefix: prefix, iface: net.Interface{Name: iface}}
}

// Issue #2: with a ULA listed before the global address, the global address must be chosen.
func TestChoosePublicIPv6PrefersGlobalOverULA(t *testing.T) {
	candidates := []ipv6Candidate{
		candidate(t, "fe80::1/64", "eth0"),
		candidate(t, "fd00:1::1/64", "eth0"),
		candidate(t, "2001:db8:1::1/64", "eth1"),
	}

	chosen, err := choosePublicIPv6(candidates)
	if err != nil {
		t.Fatal(err)
	}

	if chosen.prefix.String() != "2001:db8:1::/64" || chosen.iface.Name != "eth1" {
		t.Errorf("chose %s on %s, want 2001:db8:1::/64 on eth1", chosen.prefix, chosen.iface.Name)
	}
}

func TestChoosePublicIPv6FallsBackToULA(t *testing.T) {
	candidates := []ipv6Candidate{
		candidate(t, "fe80::1/64", "eth0"),
		candidate(t, "fd00:1::1/64", "eth0"),
	}

	chosen, err := choosePublicIPv6(candidates)
	if err != nil {
		t.Fatal(err)
	}

	if chosen.prefix.String() != "fd00:1::/64" {
		t.Errorf("chose %s, want fd00:1::/64", chosen.prefix)
	}
}

func TestChoosePublicIPv6WithoutAddresses(t *testing.T) {
	candidates := []ipv6Candidate{candidate(t, "fe80::1/64", "eth0")}

	if _, err := choosePublicIPv6(candidates); err == nil {
		t.Error("expected an error with only a link-local address")
	}
}

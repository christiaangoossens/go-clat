package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"slices"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func isNetLinkAvailable() bool {
	// Check if the netlink library can list links
	_, err := netlink.LinkList()
	return err == nil
}

func getNAT64PrefixFromDNS() (*net.IPNet, error) {
	// Request ipv4only.arpa AAAA records to get the NAT64 prefix
	log.Printf("Discovering the NAT64 prefix from your DNS64 server...")
	ips, err := net.LookupIP("ipv4only.arpa")
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		// Check if the IP address is IPv6
		if ip.To4() == nil { // Ensure it's an IPv6 address
			_, ipNet, err := net.ParseCIDR(ip.String() + "/96")
			if err != nil {
				return nil, err
			}

			log.Printf("Discovered NAT64 prefix %s", ipNet)
			return ipNet, nil
		}
	}

	return nil, fmt.Errorf(
		"No AAAA records found for ipv4only.arpa, do you have your DNS64 implementation configured correctly?",
	)
}

// getNAT64Prefix returns the configured prefix, or discovers it through DNS64 when none is configured.
func getNAT64Prefix(configured string) (*net.IPNet, error) {
	if configured != "" {
		_, prefix, err := net.ParseCIDR(configured)
		if err != nil {
			return nil, fmt.Errorf("Invalid NAT64 prefix: %w", err)
		}

		// Check here, before go-clat changes anything on the system, which prefixes RFC 6052 allows.
		length, _ := prefix.Mask.Size()
		if prefix.IP.To4() != nil || !slices.Contains([]int{32, 40, 48, 56, 64, 96}, length) {
			return nil, fmt.Errorf("Invalid NAT64 prefix %s: it must be IPv6 and /32, /40, /48, /56, /64 or /96", configured)
		}

		log.Printf("Using the configured NAT64 prefix %s", prefix)
		return prefix, nil
	}

	// Get the NAT64 prefix from the DNS64 server
	nat64Prefix, err := getNAT64PrefixFromDNS()
	if err != nil {
		log.Print(err)

		// Use the wellknown prefix of 64:ff9b::/96
		wellknownPrefix := "64:ff9b::/96"
		log.Printf("Falling back to the well-known NAT64 prefix %s", wellknownPrefix)
		_, nat64Prefix, err = net.ParseCIDR(wellknownPrefix)
		if err != nil {
			return nil, err
		}
	}

	return nat64Prefix, nil
}

func createIPv4Tun(tunnelAddr net.IP) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, errors.New("Failed to create TUN interface: " + err.Error())
	}

	ifaceName := ifce.Name()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.New("Failed to get link: " + err.Error())
	}

	addr, err := netlink.ParseAddr(tunnelAddr.String() + "/32")
	if err != nil {
		return nil, errors.New("Failed to parse the static CLAT IPv4 address: " + err.Error())
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, errors.New("Failed to add the static CLAT IPv4 address: " + err.Error())
	}

	// Set MTU to 1252 (allow for 20-byte IPv4 header and IPv6 fragment header)
	if err := netlink.LinkSetMTU(link, 1252); err != nil {
		return nil, errors.New("Failed to set the MTU: " + err.Error())
	}

	// Disallow multicast
	if err := netlink.LinkSetMulticastOff(link); err != nil {
		return nil, errors.New("Failed to set multicast off: " + err.Error())
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, errors.New("Failed to set the link state as up: " + err.Error())
	}

	// Add a default route
	route := &netlink.Route{
		Dst:       nil,
		Gw:        tunnelAddr,
		LinkIndex: link.Attrs().Index,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return nil, errors.New("Failed to add default route: " + err.Error())
	}

	return ifce, nil
}

func createIPv6Tun(tunnelAddr net.IP) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, errors.New("Failed to create TUN interface: " + err.Error())
	}

	ifaceName := ifce.Name()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.New("Failed to get link: " + err.Error())
	}

	addr, err := netlink.ParseAddr(tunnelAddr.String() + "/64")
	if err != nil {
		return nil, errors.New("Failed to parse the static CLAT IPv4 address: " + err.Error())
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, errors.New("Failed to add the static CLAT IPv6 address: " + err.Error())
	}

	// Disallow multicast
	if err := netlink.LinkSetMulticastOff(link); err != nil {
		return nil, errors.New("Failed to set multicast off: " + err.Error())
	}

	// Set MTU to 1500, the usual MTU of the uplink, so the kernel can forward any packet from the internet into this
	// tun. With a smaller MTU it would answer Packet Too Big and drop the first large UDP reply. Outgoing packets do not
	// use this tun; their size is limited by the IPv4 tun.
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		return nil, errors.New("Failed to set the MTU: " + err.Error())
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, errors.New("Failed to set the link state as up: " + err.Error())
	}

	return ifce, nil
}

// Register an IPv6 address on a given interface
func addIPv6Address(iface *net.Interface, addr net.IP) error {
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return errors.New("Failed to get link: " + err.Error())
	}

	ipNet := &net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(128, 128),
	}

	netlinkAddr := &netlink.Addr{
		IPNet: ipNet,
	}

	if err := netlink.AddrAdd(link, netlinkAddr); err != nil {
		return errors.New("Failed to add the IPv6 address: " + err.Error())
	}

	return nil
}

// Remove IPv6 address from a given interface
func removeIPv6Address(iface *net.Interface, addr net.IP) error {
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return errors.New("Failed to get link: " + err.Error())
	}

	ipNet := &net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(128, 128),
	}

	netlinkAddr := &netlink.Addr{
		IPNet: ipNet,
	}

	if err := netlink.AddrDel(link, netlinkAddr); err != nil {
		return errors.New("Failed to remove the IPv6 address: " + err.Error())
	}

	return nil
}

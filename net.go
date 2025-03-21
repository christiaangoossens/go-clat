package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"

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

func getNAT64Prefix() (*net.IPNet, error) {
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

	// Set MTU to 1260 (allow for 20-byte IPv4 header)
	if err := netlink.LinkSetMTU(link, 1260); err != nil {
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

	// Set MTU to 1280
	if err := netlink.LinkSetMTU(link, 1280); err != nil {
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

// Use ip6tables to add necessary rules
func configureIptables(ip1 net.IP, ip2 net.IP, pubFace string) error {
	// Add a DNAT rule to forward packets from ip1 to ip2
	err := exec.Command(
		"ip6tables",
		"-t", "nat",
		"-I", "POSTROUTING",
		"-o", pubFace,
		"-s", ip2.String(),
		"-j", "SNAT",
		"--to-source", ip1.String(),
	).Run()

	if err != nil {
		return errors.New("Failed to add the SNAT rule: " + err.Error())
	}

	return nil
}

// Remove the iptables config
func deconfigureIptables(ip1 net.IP, ip2 net.IP, pubFace string) error {
	// Remove the DNAT rule
	err := exec.Command(
		"ip6tables",
		"-t", "nat",
		"-D", "POSTROUTING",
		"-o", pubFace,
		"-s", ip2.String(),
		"-j", "SNAT",
		"--to-source", ip1.String(),
	).Run()

	if err != nil {
		return errors.New("Failed to remove the SNAT rule: " + err.Error())
	}

	return nil
}

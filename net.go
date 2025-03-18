package main

import (
	"fmt"
	"log"
	"net"
)

func getIPv6Src() (net.IP, string, error) {
	// Get the IPv6 address from any interface that has a global IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, "", err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
				return ipNet.IP, iface.Name, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no global IPv6 address found")
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

package main

import (
	"fmt"
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

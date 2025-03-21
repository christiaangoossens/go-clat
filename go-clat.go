package main

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func app() int {
	log.Printf("Starting go-clat")

	// Check pre-requisites
	if !isNetLinkAvailable() {
		log.Print("This operating system is currently not supported by go-clat. We need netlink support.")
		return 1
	}

	// Check if ip6tables exists
	_, err := exec.LookPath("ip6tables")
	if err != nil {
		log.Print("ip6tables not found, please install it")
		return 1
	}

	// Obtain the NAT64 prefix
	nat64Net, err := getNAT64Prefix()
	if err != nil {
		log.Print(err)
		return 1
	}

	// Generate the IPv4 tunnel
	ipAddr := getIPv4TunAddress()
	iface, err := createIPv4Tun(ipAddr)

	if err != nil {
		log.Print(err)
		return 1
	}

	// Generate the IPv6 addrs to use to send & receive packets
	ipv6Prefix, ipv6Iface, err := getPublicIPv6()
	if err != nil {
		log.Print(err)
		return 1
	}

	publicIPv6Addr, err := generateIPv6Address(ipAddr, ipv6Prefix)
	if err != nil {
		log.Print(err)
		return 1
	}

	// Generate the IPv6 tunnel
	tunnelIPv6NetIP, tunnelIPv6NetSrcIP := getIPv6TunNet(ipAddr)
	iface6, err6 := createIPv6Tun(tunnelIPv6NetIP)

	if err6 != nil {
		log.Print(err)
		return 1
	}

	// Check if ipv6 forwarding is enabled for the interface found
	// Otherwise no packets will come in
	settingName := "net.ipv6.conf.all.forwarding=1"

	cmd := exec.Command("sysctl", "-n", settingName)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error checking IPv6 forwarding: %v", err)
		return 1
	}

	if string(output) != "1\n" {
		// Automatically enable forwarding by running sysctl -w
		cmd := exec.Command("sysctl", "-w", settingName)
		if err := cmd.Run(); err != nil {
			log.Printf("Error enabling IPv6 forwarding: %v", err)
			log.Printf("IPv6 forwarding is not enabled. Please enable it by running: sysctl -w %s", settingName)
			return 1
		}
	}

	// Log all addresses for debugging
	log.Printf("IPv6 public address: %s", publicIPv6Addr)
	log.Printf("IPv6 interface: %s", ipv6Iface.Name)

	// Add the public IPv6 to the actual interface
	err = addIPv6Address(ipv6Iface, publicIPv6Addr)
	if err != nil {
		log.Print(err)
		return 1
	}

	// Remove the IPv6 when this program exits
	defer func() {
		if err := removeIPv6Address(ipv6Iface, publicIPv6Addr); err != nil {
			log.Printf("Error removing IPv6 address: %v", err)
		}
		log.Printf("Removed extra IPv6 address")
	}()

	// Perform the neccesary firewall settings
	err = configureIptables(publicIPv6Addr, tunnelIPv6NetSrcIP, ipv6Iface.Name)
	if err != nil {
		log.Print(err)
		return 1
	}

	defer func() {
		if err := deconfigureIptables(publicIPv6Addr, tunnelIPv6NetSrcIP, ipv6Iface.Name); err != nil {
			log.Printf("Error removing IPv6 address: %v", err)
		}
		log.Printf("Removed IPv6 iptables config for go-clat")
	}()

	/** ====
	 * SETUP DONE!
	 * =====
	 */

	// All done, now listen for packets!
	go func() {
		// IPv6
		log.Printf("Listening for incoming IPv6 packets on %s", iface6.Name())
		packet := make([]byte, 2000)
		for {
			n, err := iface6.Read(packet)
			if err != nil {
				log.Fatal(err)
			}

			// Parse the IPv6 packet
			// Use gopacket to parse the IPv4 packet
			packetData := packet[:n]
			packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv6, gopacket.Default)

			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			if ipLayer == nil {
				// Not IPv6 packet, ignore because we are only translating IPv6 here
				continue
			}

			ip, _ := ipLayer.(*layers.IPv6)

			// If dest is not the tunneladdr, drop it, we are only interested in return packets
			if !ip.DstIP.Equal(tunnelIPv6NetSrcIP) {
				continue
			}

			// If the packet is not from the nat64 prefix, drop it
			if !nat64Net.Contains(ip.SrcIP) {
				continue
			}

			// Recreate the IPv4 src address
			ipv4SrcIP := ip.SrcIP[12:]

			// Translate the packet to IPv4
			result := translateIPv6(packet, ipv4SrcIP, ipAddr)

			// Put the resulting packet back onto the IPv4 interface
			if result == nil {
				log.Printf("Dropping IPv6 packet, didn't translate")
				continue
			}

			_, err = iface.Write(result)
			if err != nil {
				log.Printf("Error writing packet to IPv4 interface: %v", err)
			}
		}
	}()

	go func() {
		// IPv4
		log.Printf("Listening for incoming IPv4 packets on %s", iface.Name())
		packet := make([]byte, 2000)
		for {
			n, err := iface.Read(packet)
			if err != nil {
				log.Fatal(err)
			}

			// Parse the IPv4 packet
			// Use gopacket to parse the IPv4 packet
			packetData := packet[:n]
			packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				// Not IPv4 packet, ignore because we are only translating IPv4 here
				continue
			}

			ip, _ := ipLayer.(*layers.IPv4)

			// https://datatracker.ietf.org/doc/html/rfc6145
			// Safeguards

			// If src is wrong, drop the packet
			if !ip.SrcIP.Equal(ipAddr) {
				continue
			}

			// If multicast, drop the packet
			if ip.DstIP.IsMulticast() {
				continue
			}

			// If the packet is fragmented ICMP, drop it
			// Source: Fragmented ICMP/ICMPv6 packets will not be translated by the IP/ICMP translator.
			if ip.Protocol == layers.IPProtocolICMPv4 &&
				(ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0) {
				log.Printf("Dropping fragmented ICMP packet")
				continue
			}

			// Drop packet if the packet is not a TCP, UDP or ICMP packet
			if ip.Protocol != layers.IPProtocolTCP &&
				ip.Protocol != layers.IPProtocolUDP &&
				ip.Protocol != layers.IPProtocolICMPv4 {
				log.Printf("Dropping packet with unsupported protocol %d", ip.Protocol)
				continue
			}

			// Map the IPv4 destination onto the NAT64 prefix
			ipv4Bytes := ip.DstIP.To4()
			if ipv4Bytes == nil {
				log.Printf("Invalid IPv4 address: %s", ip.DstIP)
				continue
			}

			nat64DstIP := nat64Net.IP
			copy(nat64DstIP[12:], ipv4Bytes)

			log.Printf("Translating IPv4 packet to %s (%s), Flags: %s, ID: %d, TTL: %d, Protocol: %s",
				ip.DstIP, nat64DstIP, ip.Flags, ip.Id, ip.TTL, ip.Protocol)

			// Translate the packet to IPv6
			result := translateIPv4(packet, tunnelIPv6NetSrcIP, nat64DstIP)

			if result == nil {
				// We shouldn't translate this packet
				log.Printf("Dropping IPv4 packet %d, didn't translate", ip.Id)
				continue
			}

			// Open a raw socket for sending the translated packet
			fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
			if err != nil {
				log.Printf("Error creating raw socket: %v", err)
				continue
			}

			// Destination address for the packet
			addr := &syscall.SockaddrInet6{
				Port: 0,
				Addr: [16]byte{},
			}
			copy(addr.Addr[:], nat64DstIP)

			// Send the packet
			err = syscall.Sendto(fd, result, 0, addr)
			syscall.Close(fd)

			if err != nil {
				log.Printf("Error sending translated packet for %d: %v", ip.Id, err)
			}
		}
	}()

	gracefulShutdown := make(chan os.Signal, 1)
	signal.Notify(gracefulShutdown, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	<-gracefulShutdown
	log.Println("Got a shutdown request, exiting gracefully...")
	return 0
}

func main() {
	os.Exit(app())
}

package main

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
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
	ipv4TunnelAddr := getIPv4TunAddress()
	iface, err := createIPv4Tun(ipv4TunnelAddr)

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

	publicIPv6Addr, err := generateIPv6Address(ipv4TunnelAddr, ipv6Prefix)
	if err != nil {
		log.Print(err)
		return 1
	}

	// Generate the IPv6 tunnel
	tunnelIPv6NetIP, tunnelIPv6NetSrcIP := getIPv6TunNet(ipv4TunnelAddr)
	iface6, err := createIPv6Tun(tunnelIPv6NetIP)
	if err != nil {
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

	translator, err := newTranslator(nat64Net, publicIPv6Addr, tunnelIPv6NetSrcIP)
	if err != nil {
		log.Printf("Error creating translator: %v", err)
		return 1
	}

	sender, err := newIPv6Sender()
	if err != nil {
		log.Print(err)
		return 1
	}
	defer sender.Close()

	log.Printf("Translating between %s and %s", iface.Name(), iface6.Name())
	go func() {
		log.Fatal(translateIPv4Loop(translator, iface, sender.Send))
	}()

	go func() {
		log.Fatal(translateIPv6Loop(translator, iface6, iface, tunnelIPv6NetSrcIP))
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

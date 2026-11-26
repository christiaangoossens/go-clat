package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// app runs go-clat until it gets a shutdown signal. An empty nat64Prefix means: discover it through DNS64.
func app(nat64Prefix string) int {
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
	nat64Net, err := getNAT64Prefix(nat64Prefix)
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
	ipv6Prefix, ipv6Iface, err := getPublicIPv6(nat64Net)
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

	// Forward the replies from the uplink to the IPv6 tun, otherwise no packets will come in
	forwarding, err := enableIPv6Forwarding()
	if err != nil {
		log.Printf("Error enabling IPv6 forwarding: %v", err)
		return 1
	}

	defer func() {
		if err := forwarding.restore(); err != nil {
			log.Printf("Error restoring the IPv6 forwarding settings: %v", err)
			return
		}

		log.Printf("Restored the IPv6 forwarding settings")
	}()

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
			return
		}

		log.Printf("Removed extra IPv6 address")
	}()

	// SNAT to the public address, and let the replies through the firewall
	rules := firewallRules(publicIPv6Addr, tunnelIPv6NetSrcIP, ipv6Iface.Name, iface6.Name())
	if err := configureFirewall(rules); err != nil {
		log.Printf("Error adding the ip6tables rules: %v", err)
		return 1
	}

	defer func() {
		if err := deconfigureFirewall(rules); err != nil {
			log.Printf("Error removing the ip6tables rules: %v", err)
			return
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

	// The loops only return on an error. Returning from app then runs the cleanup above, which log.Fatal would skip.
	log.Printf("Translating between %s and %s", iface.Name(), iface6.Name())
	translationErrors := make(chan error, 2)
	go func() { translationErrors <- translateIPv4Loop(translator, iface, sender.Send) }()
	go func() { translationErrors <- translateIPv6Loop(translator, iface6, iface, tunnelIPv6NetSrcIP) }()

	gracefulShutdown := make(chan os.Signal, 1)
	signal.Notify(gracefulShutdown, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-gracefulShutdown:
		log.Println("Got a shutdown request, exiting gracefully...")
		return 0

	case err := <-translationErrors:
		log.Printf("Translation stopped: %v", err)
		return 1
	}
}

func main() {
	nat64Prefix := flag.String("nat64-prefix", "", "NAT64 prefix to use, such as 64:ff9b::/96 (default: discover it through DNS64)")
	flag.Parse()

	os.Exit(app(*nat64Prefix))
}

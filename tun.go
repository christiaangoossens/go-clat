package main

import (
	"errors"
	"log"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func createIPv4Tun() (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, errors.New("Failed to create TUN interface: " + err.Error())
	}

	ifaceName := ifce.Name()

	log.Printf("Interface Name: %s\n", ifaceName)

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.New("Failed to get link: " + err.Error())
	}

	addr, err := netlink.ParseAddr(
		"192.0.0.1/24",
	) // TODO: Should actually be 192.0.0.1/32, but that's hard to test with
	if err != nil {
		return nil, errors.New("Failed to parse the static CLAT address: " + err.Error())
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, errors.New("Failed to add the static CLAT address: " + err.Error())
	}

	// TODO: Should we also add a default route for IPv4 over this interface?

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, errors.New("Failed to set the link state as up: " + err.Error())
	}

	return ifce, nil
}

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const ipv6ConfDir = "/proc/sys/net/ipv6/conf"

// sysctlChange is a sysctl go-clat changed, with the value to restore.
type sysctlChange struct {
	path     string
	previous string
}

// forwardingSettings are the changes enableIPv6Forwarding made.
type forwardingSettings struct {
	changes []sysctlChange
}

// enableIPv6Forwarding enables IPv6 forwarding, so the kernel passes the replies from the uplink to the IPv6 tun.
//
// Linux before 6.17 only forwards IPv6 when forwarding is enabled for all interfaces. A forwarding interface ignores
// Router Advertisements unless accept_ra is 2, and enabling forwarding removes the default routes learned from them at
// once. So every interface that accepts them now (accept_ra 1 without forwarding) gets accept_ra 2 first. Interfaces
// where a network manager handles them (accept_ra 0) are left alone, and so is a host that already forwards.
func enableIPv6Forwarding() (*forwardingSettings, error) {
	settings := &forwardingSettings{}
	allForwarding := filepath.Join(ipv6ConfDir, "all", "forwarding")

	forwarding, err := readSysctl(allForwarding)
	if err != nil {
		return nil, err
	}

	if forwarding == "1" {
		return settings, nil
	}

	if err := settings.keepAcceptingRouterAdvertisements(); err != nil {
		return nil, errors.Join(err, settings.restore())
	}

	if err := settings.rememberForwardingInterfaces(); err != nil {
		return nil, errors.Join(err, settings.restore())
	}

	if err := settings.set(allForwarding, "0", "1"); err != nil {
		return nil, errors.Join(err, settings.restore())
	}

	return settings, nil
}

// keepAcceptingRouterAdvertisements sets accept_ra from 1 to 2 on "default" (for interfaces that appear later) and on
// every interface that does not forward yet.
func (s *forwardingSettings) keepAcceptingRouterAdvertisements() error {
	names, err := confNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		forwarding, err := readSysctl(filepath.Join(ipv6ConfDir, name, "forwarding"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}

		if err != nil {
			return err
		}

		if forwarding == "0" {
			if err := s.set(filepath.Join(ipv6ConfDir, name, "accept_ra"), "1", "2"); err != nil {
				return err
			}
		}
	}

	return nil
}

// rememberForwardingInterfaces records the interfaces that already forward. Enabling forwarding for all interfaces
// does not change them, but restoring it disables forwarding on every interface, so they must be enabled again.
func (s *forwardingSettings) rememberForwardingInterfaces() error {
	names, err := confNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		path := filepath.Join(ipv6ConfDir, name, "forwarding")

		forwarding, err := readSysctl(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}

		if err != nil {
			return err
		}

		if forwarding == "1" {
			s.changes = append(s.changes, sysctlChange{path: path, previous: "1"})
		}
	}

	return nil
}

// set changes a sysctl that is from to to, and remembers that. Other values, and interfaces that disappeared, are
// left alone.
func (s *forwardingSettings) set(path, from, to string) error {
	current, err := readSysctl(path)
	if errors.Is(err, fs.ErrNotExist) || err == nil && current != from {
		return nil
	}

	if err != nil {
		return err
	}

	err = os.WriteFile(path, []byte(to), 0o644)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	log.Printf("Set %s to %s (was %s)", strings.TrimPrefix(path, "/proc/sys/"), to, from)
	s.changes = append(s.changes, sysctlChange{path: path, previous: from})

	return nil
}

// restore undoes the changes in reverse order. Interfaces that no longer exist are skipped.
func (s *forwardingSettings) restore() error {
	var errs []error

	for i := len(s.changes) - 1; i >= 0; i-- {
		change := s.changes[i]

		err := os.WriteFile(change.path, []byte(change.previous), 0o644)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("restoring %s: %w", change.path, err))
		}
	}

	return errors.Join(errs...)
}

// confNames returns "default" followed by the interfaces, without "all".
func confNames() ([]string, error) {
	entries, err := os.ReadDir(ipv6ConfDir)
	if err != nil {
		return nil, err
	}

	names := []string{"default"}
	for _, entry := range entries {
		if entry.Name() != "all" && entry.Name() != "default" {
			names = append(names, entry.Name())
		}
	}

	return names, nil
}

func readSysctl(path string) (string, error) {
	value, err := os.ReadFile(path)

	return strings.TrimSpace(string(value)), err
}

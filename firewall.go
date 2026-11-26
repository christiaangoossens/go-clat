package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// firewallRule is an ip6tables rule go-clat adds while it runs.
type firewallRule struct {
	table string
	chain string
	spec  []string
}

// firewallRules returns go-clat's ip6tables rules:
//   - SNAT translated packets from the tunnel address to the public address on the uplink;
//   - accept the replies forwarded from the uplink into the IPv6 tun, also when the FORWARD policy is DROP (Docker);
//   - accept go-clat's own ICMP errors, which it writes into the IPv6 tun from the public address.
func firewallRules(public, tunnel net.IP, uplink, ipv6Tun string) []firewallRule {
	return []firewallRule{
		{"nat", "POSTROUTING", []string{"-o", uplink, "-s", tunnel.String(), "-j", "SNAT", "--to-source", public.String()}},
		{"filter", "FORWARD", []string{"-i", uplink, "-o", ipv6Tun, "-d", tunnel.String(), "-j", "ACCEPT"}},
		{"filter", "FORWARD", []string{"-i", ipv6Tun, "-o", uplink, "-s", public.String(), "-j", "ACCEPT"}},
	}
}

// configureFirewall adds the rules in front of existing ones. When one fails, the ones already added are removed.
func configureFirewall(rules []firewallRule) error {
	for i, rule := range rules {
		if err := rule.run("-I"); err != nil {
			return errors.Join(err, deconfigureFirewall(rules[:i]))
		}
	}

	return nil
}

// deconfigureFirewall removes the rules, also when removing one of them fails.
func deconfigureFirewall(rules []firewallRule) error {
	var errs []error
	for _, rule := range rules {
		errs = append(errs, rule.run("-D"))
	}

	return errors.Join(errs...)
}

// run inserts (-I) or deletes (-D) the rule.
func (r firewallRule) run(action string) error {
	args := append([]string{"-t", r.table, action, r.chain}, r.spec...)

	output, err := exec.Command("ip6tables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip6tables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}

	return nil
}

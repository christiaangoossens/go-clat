# Golang based CLAT translator (go-clat)
Allows the use of IPv4 literals on an IPv6 (NAT64 + DNS64) only network without any manual configuration. It will autodiscover the prefix using `ipv4only.arpa` and configure your machine to work automatically. If you know your NAT64 prefix, you can skip discovery with `-nat64-prefix`, for example `./go-clat -nat64-prefix 64:ff9b::/96`.

## Requirements
- Linux with netlink support and `ip6tables`, run as root.
- go-clat enables IPv6 forwarding for all interfaces while it runs, because Linux (before 6.17) cannot forward IPv6 for a single interface. Interfaces that get their default route from Router Advertisements through the kernel keep accepting them (`accept_ra` is set to 2). go-clat restores these settings when it stops.
- A global IPv6 prefix from SLAAC (a /64, or at most /80). go-clat adds its own address from that prefix to your interface, so it does not work with only a DHCPv6 /128 address: the network would not route traffic for an address it did not hand out. A global address is preferred over a unique local one (fc00::/7); a unique local prefix is only used when there is no global one, for example with NAT64 on your own router.

## Automated tests
- Unit tests: `go test ./...`
- Integration tests: `go -C integration test -count=1 ./...` runs the real go-clat binary in its own user and network namespace without IPv4, with a fake NAT64 internet. It needs no root and does not touch your network, but it does need unprivileged user namespaces (on Ubuntu 24.04 and later, AppArmor blocks them). The kernel's IPv6 NAT support (`ip6table_nat` or nf_tables NAT) must already be loaded, because a user namespace cannot load it.

## Test Instructions
1. Ensure that your network and DNS allow for NAT64. If they don't, or if you are testing on a network with IPv4 enabled, disable IPv4 first and then use `2a02:898:146:64::64` for a public example DNS64 server.
2. Check that `ping 1.1.1.1` does NOT work for you (you should see `ping: connect: Network is unreachable`)
3. Go to the last commit of this repository and go to the Github Action
4. A prebuilt binary should be available there in the artifacts
5. Download this binary to your working directory
6. Run the binary using root (for instance sudo) with `sudo ./go-clat`.
7. You should now be able to use `ping 1.1.1.1` to test.

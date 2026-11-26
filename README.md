# Golang based CLAT translator (go-clat)
> [!WARNING]  
> This is an academic project. Use in production at your own risk. It is also currently Linux only.

Allows the use of IPv4 literals on an IPv6 (NAT64 + DNS64) only network without any manual configuration. It will autodiscover the prefix using `ipv4only.arpa` and configure your machine to work automatically.

## Requirements
- Linux with netlink support, `ip6tables` and `sysctl`, run as root.
- A global IPv6 prefix from SLAAC (a /64, or at most /80). go-clat adds its own address from that prefix to your interface, so it does not work with only a DHCPv6 /128 address: the network would not route traffic for an address it did not hand out. A global address is preferred over a unique local one (fc00::/7); a unique local prefix is only used when there is no global one, for example with NAT64 on your own router.

## Test Instructions
1. Ensure that your network and DNS allow for NAT64. If they don't, or if you are testing on a network with IPv4 enabled, disable IPv4 first and then use `2a02:898:146:64::64` for a public example DNS64 server.
2. Check that `ping 1.1.1.1` does NOT work for you (you should see `ping: connect: Network is unreachable`)
3. Go to the last commit of this repository and go to the Github Action
4. A prebuilt binary should be available there in the artifacts
5. Download this binary to your working directory
6. Run the binary using root (for instance sudo) with `sudo ./go-clat`.
7. You should now be able to use `ping 1.1.1.1` to test.

# Golang based CLAT translator (go-clat)
> [!WARNING]  
> This is an academic project. Use in production at your own risk. It is also currently Linux only.

> [!NOTE]  
> ICMP, TCP and UDP work with this translator, but the implementation is incomplete. If you would be interested in implementing the remaining ICMP types from the RFC, see https://github.com/christiaangoossens/go-clat/issues/1.

Allows the use of IPv4 literals on an IPv6 (NAT64 + DNS64) only network without any manual configuration. It will autodiscover the prefix using `ipv4only.arpa` and configure your machine to work automatically.

## Test Instructions
1. Ensure that your network and DNS allow for NAT64. If they don't, or if you are testing on a network with IPv4 enabled, disable IPv4 first and then use `2a02:898:146:64::64` for a public example DNS64 server.
2. Check that `ping 1.1.1.1` does NOT work for you (you should see `ping: connect: Network is unreachable`)
3. Go to the last commit of this repository and go to the Github Action
4. A prebuilt binary should be available there in the artifacts
5. Download this binary to your working directory
6. Run the binary using root (for instance sudo) with `sudo ./go-clat`.
7. You should now be able to use `ping 1.1.1.1` to test.

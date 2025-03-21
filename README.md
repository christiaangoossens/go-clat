# Golang based CLAT translator (go-clat)
_Do not use in production settings! This is an academic project._

Allows the use of IPv4 literals on an IPv6 (NAT64 + DNS64) only network without any manual configuration. It will autodiscover the prefix using `ipv4only.arpa` and configure your machine to work automatically.

Note: This project is currently Linux only!

## Test Instructions
1. Ensure that your network and DNS allow for NAT64. If they don't, or if you are testing on a network with IPv4 enabled, disable IPv4 first and then use `2a02:898:146:64::64` for a public example DNS64 server.
2. Check that `ping 1.1.1.1` does not work for you.
3. Install golang (prebuilt binaries will be available later)
4. Build the program using `go build`
5. Run the program using root (for instance sudo) with `sudo ./go-clat`.
6. You should now be able to use `ping 1.1.1.1` to test.
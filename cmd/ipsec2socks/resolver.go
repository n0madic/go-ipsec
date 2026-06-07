package main

import (
	"net"

	ipsec "github.com/n0madic/go-ipsec"
)

// buildResolver returns a net.Resolver that performs DNS queries through the
// tunnel. The -dns override wins; otherwise the responder-pushed DNS (or
// 1.1.1.1) is used. UDP framing is handled by Client.Resolver.
func buildResolver(client *ipsec.Client, override string) (*net.Resolver, error) {
	return client.Resolver(override), nil
}

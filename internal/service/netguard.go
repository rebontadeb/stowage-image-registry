package service

import (
	"context"
	"fmt"
	"net"
)

// guardedDial refuses connections to loopback, link-local (cloud metadata endpoints included) and
// unspecified addresses, checking every address the name resolves to and then dialling the one
// it checked, so a DNS answer cannot change between the check and the connection. Private ranges
// stay reachable: internal mirrors and registries are legitimate sources.
func guardedDial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no address for %s", host)
		}
		for _, ip := range ips {
			if ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified() {
				return nil, fmt.Errorf("refusing to connect to %s (%s)", host, ip.IP)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

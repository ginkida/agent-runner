package netutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fe80::/10", "fc00::/7",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
}

// IsPrivateIP returns true if ip belongs to a private/reserved range.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// SafeTransport returns an *http.Transport that blocks connections to private IPs.
// DNS resolution happens at dial time to prevent DNS rebinding.
func SafeTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for host %q", host)
			}
			for _, ip := range ips {
				if IsPrivateIP(ip.IP) {
					return nil, fmt.Errorf("connection to private IP %s is blocked", ip.IP)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
}

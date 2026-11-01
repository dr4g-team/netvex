package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResolvedAddresses = 64

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

var (
	ErrBlocked         = errors.New("destination blocked")
	ErrResolve         = errors.New("destination resolution failed")
	unsafeIPv4Prefixes = [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	unsafeIPv6Prefixes = [...]netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("100:0:0:1::/64"),
		netip.MustParsePrefix("2001::/32"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:10::/28"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
)

func blocked(message string) error { return fmt.Errorf("%w: %s", ErrBlocked, message) }

type Policy struct {
	AllowPrivate bool
	AllowedHosts map[string]struct{}
	Resolver     Resolver
}

type Destination struct {
	URL         *url.URL
	Host        string
	Port        string
	IP          netip.Addr
	Resolved    []netip.Addr
	DNSDuration time.Duration
}

func New(allowPrivate bool, allowed []string) *Policy {
	m := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		m[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))] = struct{}{}
	}
	return &Policy{AllowPrivate: allowPrivate, AllowedHosts: m, Resolver: net.DefaultResolver}
}

func (p *Policy) Resolve(ctx context.Context, raw string) (Destination, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Destination{}, blocked("invalid destination URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Destination{}, blocked("destination scheme must be http or https")
	}
	if u.User != nil {
		return Destination{}, blocked("destination credentials are forbidden")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if len(p.AllowedHosts) > 0 {
		if _, ok := p.AllowedHosts[host]; !ok {
			return Destination{}, blocked(fmt.Sprintf("destination host %q is not in the allowlist", host))
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if n, e := strconv.ParseUint(port, 10, 16); e != nil || n == 0 {
		return Destination{}, blocked("destination port must be between 1 and 65535")
	}
	start := time.Now()
	addrs, err := p.Resolver.LookupNetIP(ctx, "ip", host)
	dnsDuration := time.Since(start)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: %v", ErrResolve, err)
	}
	if len(addrs) == 0 {
		return Destination{}, fmt.Errorf("%w: no addresses", ErrResolve)
	}
	approved := make([]netip.Addr, 0, min(len(addrs), maxResolvedAddresses))
	for _, ip := range addrs {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return Destination{}, blocked(fmt.Sprintf("destination %q resolved to an invalid service address", host))
		}
		if !p.AllowPrivate && IsUnsafe(ip) {
			return Destination{}, blocked(fmt.Sprintf("destination %q resolved to blocked address %s", host, ip))
		}
		duplicate := false
		for _, existing := range approved {
			if existing == ip {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(approved) == maxResolvedAddresses {
			return Destination{}, fmt.Errorf("%w: destination returned more than %d unique addresses", ErrResolve, maxResolvedAddresses)
		}
		approved = append(approved, ip)
	}
	return Destination{URL: u, Host: host, Port: port, IP: approved[0], Resolved: approved, DNSDuration: dnsDuration}, nil
}

func IsUnsafe(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip.Is4() {
		for _, prefix := range unsafeIPv4Prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
	} else {
		for _, prefix := range unsafeIPv6Prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

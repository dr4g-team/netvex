package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type resolver struct{ ips []netip.Addr }

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func TestPolicyBlocksUnsafeAndRebindingSet(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}}
	if _, err := p.Resolve(context.Background(), "https://allowed.test/"); err == nil {
		t.Fatal("expected mixed resolution block")
	}
}
func TestPolicyAllowlist(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	if _, err := p.Resolve(context.Background(), "https://other.test/"); err == nil {
		t.Fatal("expected allowlist block")
	}
	if _, err := p.Resolve(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("expected scheme block")
	}
}

func TestPolicyDeduplicatesAndBoundsResolvedAddresses(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	address := netip.MustParseAddr("93.184.216.34")
	p.Resolver = resolver{[]netip.Addr{address, address}}
	destination, err := p.Resolve(context.Background(), "https://allowed.test/")
	if err != nil || len(destination.Resolved) != 1 || destination.IP != address {
		t.Fatalf("destination=%+v err=%v", destination, err)
	}
	addresses := make([]netip.Addr, maxResolvedAddresses+1)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{8, 1, byte(index >> 8), byte(index)})
	}
	p.Resolver = resolver{addresses}
	if _, err := p.Resolve(context.Background(), "https://allowed.test/"); !errors.Is(err, ErrResolve) {
		t.Fatalf("excessive address set err=%v", err)
	}
	p = New(true, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{{}}}
	if _, err := p.Resolve(context.Background(), "https://allowed.test/"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("invalid address with private override err=%v", err)
	}
}
func TestUnsafeRanges(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.88.99.1",
		"::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:2::1", "2001:10::1", "2001:db8::1", "2002:7f00:1::1",
		"3fff::1", "5f00::1", "fc00::1",
	} {
		if !IsUnsafe(netip.MustParseAddr(s)) {
			t.Errorf("not blocked: %s", s)
		}
	}
	if IsUnsafe(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP blocked")
	}
}

func TestInvalidDestinationPort(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if _, err := p.Resolve(context.Background(), "https://allowed.test:99999/"); err == nil {
		t.Fatal("invalid port accepted")
	}
}

func BenchmarkIsUnsafe(b *testing.B) {
	addresses := [...]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2001:db8::10"),
	}
	b.ReportAllocs()
	for index := range b.N {
		_ = IsUnsafe(addresses[index%len(addresses)])
	}
}

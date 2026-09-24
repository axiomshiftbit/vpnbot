// SPDX-License-Identifier: GPL-3.0-or-later
package route

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type policyDNS struct {
	adapter.DNSRouter
	calls map[string]int
}

func (d *policyDNS) Lookup(_ context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.calls[domain]++
	switch domain {
	case "public.test":
		return []netip.Addr{netip.MustParseAddr("11.77.0.2")}, nil
	case "private.test":
		return []netip.Addr{netip.MustParseAddr("10.10.0.7")}, nil
	case "blocked.test":
		return []netip.Addr{netip.MustParseAddr("11.77.0.3")}, nil
	case "rebind.test":
		if d.calls[domain] == 1 {
			return []netip.Addr{netip.MustParseAddr("11.77.0.2")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, io.EOF
}

func policyRouter(t *testing.T) (*Router, *policyDNS) {
	t.Helper()
	dns := &policyDNS{calls: make(map[string]int)}
	r := &Router{dns: dns, logger: log.NewNOPFactory().Logger()}
	for _, text := range []string{`{"action":"resolve"}`, `{"ip_is_private":true,"action":"reject"}`, `{"ip_cidr":["11.77.0.3/32","100.64.0.0/10"],"action":"reject"}`} {
		var options option.Rule
		if err := json.UnmarshalContext(context.Background(), []byte(text), &options); err != nil {
			t.Fatal(err)
		}
		rule, err := R.NewRule(context.Background(), r.logger, options, false)
		if err != nil {
			t.Fatal(err)
		}
		r.rules = append(r.rules, rule)
	}
	return r, dns
}

func TestVPNBotPacketDestinations(t *testing.T) {
	r, dns := policyRouter(t)
	base := adapter.InboundContext{User: "user", Destination: M.ParseSocksaddr("11.77.0.2:9999"), DestinationAddressMatch: true}
	for _, host := range []string{"10.10.0.7", "127.0.0.1", "169.254.169.254", "100.100.100.200", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "private.test", "blocked.test", "11.77.0.3"} {
		_, err := r.checkPacketDestination(context.Background(), base, M.ParseSocksaddrHostPort(host, 9999))
		if err == nil {
			t.Fatalf("destination %s allowed after a public first destination", host)
		}
	}
	checked, err := r.checkPacketDestination(context.Background(), base, M.ParseSocksaddr("public.test:9999"))
	if err != nil || checked.Fqdn != "" || checked.Addr.String() != "11.77.0.2" || dns.calls["public.test"] != 1 {
		t.Fatal("resolved destination is not pinned", checked, err)
	}
	_, err = r.checkPacketDestination(context.Background(), base, M.ParseSocksaddr("rebind.test:9999"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.checkPacketDestination(context.Background(), base, M.ParseSocksaddr("rebind.test:9999"))
	if err == nil {
		t.Fatal("changed DNS answer bypassed policy")
	}
}

type packetSequence struct {
	N.PacketConn
	packets []string
	index   int
}

func (s *packetSequence) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if s.index == len(s.packets) {
		return M.Socksaddr{}, io.EOF
	}
	packet := s.packets[s.index]
	s.index++
	buffer.WriteString(packet)
	return M.ParseSocksaddr(packet), nil
}

// Metadata traversal is allowed; actual packet copying must not reach this reader.
type bypassReader struct{}

func (b *bypassReader) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	panic("policy bypassed through Upstream")
}
func (s *packetSequence) Upstream() any { return &bypassReader{} }

type packetCollector struct {
	destinations []string
	payloads     []string
}

func (c *packetCollector) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.destinations = append(c.destinations, destination.String())
	c.payloads = append(c.payloads, string(buffer.Bytes()))
	buffer.Release()
	return nil
}

func TestVPNBotChangingUDPDestination(t *testing.T) {
	r, _ := policyRouter(t)
	source := &packetSequence{packets: []string{"11.77.0.2:9999", "private.test:9998", "11.77.0.3:9999", "::ffff:127.0.0.1:9999", "11.77.0.4:9997"}}
	// Use explicit IPv6 host parsing instead of an ambiguous unbracketed literal.
	source.packets[3] = "[::ffff:127.0.0.1]:9999"
	guarded := r.restrictPackets(context.Background(), source, adapter.InboundContext{})
	if _, ok := any(guarded).(interface{ Upstream() any }); ok {
		t.Fatal("guard exposes unwrapping")
	}
	collector := &packetCollector{}
	_, err := bufio.CopyPacket(collector, guarded)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if len(collector.destinations) != 2 || collector.destinations[0] != "11.77.0.2:9999" || collector.destinations[1] != "11.77.0.4:9997" {
		t.Fatal("incorrect packet destinations", collector.destinations)
	}
	for i, d := range collector.destinations {
		if collector.payloads[i] != d {
			t.Fatal("dropped bytes leaked into next packet")
		}
	}
}

type framedPacketConn struct {
	N.PacketConn
	payloads []string
}

func (c *framedPacketConn) FrontHeadroom() int { return 32 }
func (c *framedPacketConn) RearHeadroom() int  { return 16 }
func (c *framedPacketConn) WriterMTU() int     { return 32768 }
func (c *framedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.payloads = append(c.payloads, string(buffer.Bytes()))
	buffer.ExtendHeader(32)
	buffer.Extend(16)
	buffer.Release()
	return nil
}

func TestVPNBotFramedPacketReplies(t *testing.T) {
	// The real bufio copier must reserve room for both transport headers and
	// trailers when writing replies through the security wrapper.
	destination := &framedPacketConn{}
	guarded := &restrictedPacketConn{PacketConn: destination}
	source := &packetSequence{packets: []string{"11.77.0.2:9999", "11.77.0.3:9999"}}
	_, err := bufio.CopyPacket(guarded, source)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if len(destination.payloads) != 2 || destination.payloads[0] != source.packets[0] {
		t.Fatal("packet payload changed")
	}
	if N.CalculateMTU(nil, guarded) != 32768 {
		t.Fatal("transport MTU lost")
	}
	if _, ok := any(guarded).(interface{ Upstream() any }); ok {
		t.Fatal("guard exposes unwrapping")
	}
}

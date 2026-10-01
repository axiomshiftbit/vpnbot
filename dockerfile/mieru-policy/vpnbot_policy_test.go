// SPDX-License-Identifier: GPL-3.0-or-later
package socks5

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func TestVPNBotUDPForwardingPolicyAndShutdown(t *testing.T) {
	for _, closeControl := range []bool{false, true} {
		t.Run(map[bool]string{false: "client-close", true: "control-close"}[closeControl], func(t *testing.T) {
			listen := func() *net.UDPConn {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				return c
			}
			upstream, downstream, stranger := listen(), listen(), listen()
			server, client := net.Pipe()
			control, controlPeer := net.Pipe()
			defer server.Close()
			defer client.Close()
			defer control.Close()
			defer controlPeer.Close()
			server.SetDeadline(time.Now().Add(5 * time.Second))
			client.SetDeadline(time.Now().Add(5 * time.Second))
			policy := &Server{config: &Config{}}
			done := make(chan error, 1)
			go func() {
				done <- RunUDPForwardingLoop(upstream, common.NewPacketOverStreamTunnel(server), downstream.LocalAddr().(*net.UDPAddr), control, policy.checkDestination)
			}()
			tunnel := common.NewPacketOverStreamTunnel(client)
			packet := func(ip string) []byte {
				var b bytes.Buffer
				b.Write([]byte{0, 0, 0})
				addr := model.AddrSpec{IP: net.ParseIP(ip), Port: 9999}
				if err := addr.WriteToSocks5(&b); err != nil {
					t.Fatal(err)
				}
				b.WriteString("payload")
				return b.Bytes()
			}
			buf := make([]byte, 1024)
			for _, ip := range []string{"1.1.1.1", "127.0.0.1", "1.1.1.1"} {
				p := packet(ip)
				if _, err := tunnel.Write(p); err != nil {
					t.Fatal(err)
				}
				downstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, _, err := downstream.ReadFromUDP(buf)
				if ip == "127.0.0.1" {
					if e, ok := err.(net.Error); !ok || !e.Timeout() {
						t.Fatal("private packet was forwarded", err)
					}
				} else if err != nil || !bytes.Equal(buf[:n], p) {
					t.Fatal("public packet failed", err)
				}
			}
			p := packet("1.1.1.1")
			stranger.WriteToUDP(p, upstream.LocalAddr().(*net.UDPAddr))
			client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := tunnel.Read(buf); err == nil {
				t.Fatal("unsolicited sender accepted")
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			downstream.WriteToUDP(p, upstream.LocalAddr().(*net.UDPAddr))
			if n, err := tunnel.Read(buf); err != nil || !bytes.Equal(buf[:n], p) {
				t.Fatal("downstream response failed", err)
			}
			if closeControl {
				controlPeer.Close()
			} else {
				client.Close()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("UDP forwarding did not stop after disconnect")
			}
		})
	}
}

type changingResolver struct {
	ips   []net.IP
	calls int
}

func (r *changingResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	i := r.calls
	if i >= len(r.ips) {
		i = len(r.ips) - 1
	}
	r.calls++
	return []net.IP{r.ips[i]}, nil
}

func TestVPNBotPrivateDestinations(t *testing.T) {
	s := &Server{config: &Config{}}
	for _, ip := range []string{"0.0.0.0", "0.2.3.4", "10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.100.100.200", "224.0.0.1", "255.255.255.255", "198.18.1.1", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1"} {
		t.Run(ip, func(t *testing.T) {
			if err := s.checkDestination(&model.AddrSpec{IP: net.ParseIP(ip), Port: 80}); err == nil {
				t.Fatal("forbidden destination allowed")
			}
		})
	}
	for _, ip := range []string{"1.1.1.1", "11.77.0.2", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if err := s.checkDestination(&model.AddrSpec{IP: net.ParseIP(ip), Port: 443}); err != nil {
			t.Fatalf("public %s: %v", ip, err)
		}
	}
}

func TestVPNBotDNSRebindingAndForwarding(t *testing.T) {
	for _, command := range []byte{constant.Socks5ConnectCmd, constant.Socks5UDPAssociateCmd} {
		resolver := &changingResolver{ips: []net.IP{net.ParseIP("11.77.0.2"), net.ParseIP("127.0.0.1")}}
		s := &Server{config: &Config{Resolver: resolver, Egress: &appctlpb.Egress{Rules: []*appctlpb.EgressRule{{IpRanges: []string{"*"}, DomainNames: []string{"*"}, Action: appctlpb.EgressAction_PROXY.Enum()}}}}}
		req := &model.Request{Command: command, DstAddr: model.AddrSpec{FQDN: "changing.example", Port: 8081}}
		if command == constant.Socks5ConnectCmd {
			if err := s.checkConnectRequest(req); err != nil {
				t.Fatal(err)
			}
			decoded := &model.Request{}
			if err := decoded.ReadFromSocks5(bytes.NewReader(req.Raw)); err != nil {
				t.Fatal(err)
			}
			if decoded.DstAddr.FQDN != "" || !decoded.DstAddr.IP.Equal(resolver.ips[0]) {
				t.Fatal("forwarded request can re-resolve DNS")
			}
			if err := s.checkDestination(&req.DstAddr); err != nil {
				t.Fatal(err)
			}
		} else {
			var packet bytes.Buffer
			packet.Write([]byte{0, 0, 0})
			req.DstAddr.WriteToSocks5(&packet)
			packet.WriteString("payload")
			checked, err := checkedForwardPacket(packet.Bytes(), []destinationPolicy{s.checkDestination})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := parseSocks5UDPDatagram(checked)
			if err != nil || decoded.Addr.FQDN != "" || !decoded.Addr.IP.Equal(resolver.ips[0]) || string(decoded.Payload) != "payload" {
				t.Fatal("UDP destination not pinned")
			}
		}
		if resolver.calls != 1 {
			t.Fatalf("resolved %d times", resolver.calls)
		}
	}
}

func TestVPNBotPrivateDNSAndConfiguredReject(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "11.77.0.2"} {
		resolver := &changingResolver{ips: []net.IP{net.ParseIP(ip)}}
		s := &Server{config: &Config{Resolver: resolver, Egress: &appctlpb.Egress{Rules: []*appctlpb.EgressRule{{IpRanges: []string{"11.77.0.2/32"}, Action: appctlpb.EgressAction_REJECT.Enum()}, {IpRanges: []string{"*"}, DomainNames: []string{"*"}, Action: appctlpb.EgressAction_PROXY.Enum(), ProxyNames: []string{"warp"}}}, Proxies: []*appctlpb.EgressProxy{{Name: proto.String("warp")}}}}}
		for _, domain := range []bool{false, true} {
			dst := model.AddrSpec{IP: net.ParseIP(ip), Port: 9999}
			if domain {
				dst.IP = nil
				dst.FQDN = "controlled.example"
			}
			if err := s.checkDestination(&dst); err == nil {
				t.Fatalf("TCP destination allowed: %s domain=%v", ip, domain)
			}
			var packet bytes.Buffer
			packet.Write([]byte{0, 0, 0})
			dst.WriteToSocks5(&packet)
			packet.WriteString("payload")
			if _, err := checkedForwardPacket(packet.Bytes(), []destinationPolicy{s.checkDestination}); err == nil {
				t.Fatal("UDP bypassed destination policy")
			}
		}
	}
	if _, err := checkedForwardPacket([]byte{0, 0, 1, 1}, nil); err == nil {
		t.Fatal("fragmented malformed UDP accepted")
	}
}

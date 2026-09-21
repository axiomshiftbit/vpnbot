// SPDX-License-Identifier: GPL-3.0-or-later
// VPNBot destination isolation for the pinned official Mieru server.
package socks5

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
)

type destinationPolicy func(*model.AddrSpec) error

var isolatedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// Translation / transition addresses can conceal an IPv4 destination.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// Resolve once, then retain the checked IP for the actual TCP dial or UDP
// packet, including requests forwarded through a SOCKS egress proxy.
func (s *Server) checkDestination(dst *model.AddrSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.forwardToProxyAction(ctx, &model.Request{DstAddr: *dst}).Action == appctlpb.EgressAction_REJECT {
		return errors.New("destination rejected by egress policy")
	}
	if len(dst.IP) == 0 && dst.FQDN != "" {
		ips, err := s.config.Resolver.LookupIP(ctx, "ip", dst.FQDN)
		if err != nil {
			return errors.New("destination resolution failed")
		}
		dst.IP = common.SelectIPFromList(ips, s.config.DualStackPreference)
	}
	ip, ok := netip.AddrFromSlice(dst.IP)
	if !ok {
		return errors.New("destination has no IP address")
	}
	ip = ip.Unmap()
	// This option is only used by upstream in-process loopback tests; mita
	// does not expose or enable it in its server configuration.
	if !(ip.IsLoopback() && s.config.AllowLoopbackDestination) {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("non-public destination rejected")
		}
		for _, prefix := range isolatedRanges {
			if prefix.Contains(ip) {
				return errors.New("special-use destination rejected")
			}
		}
	}
	if s.forwardToProxyAction(ctx, &model.Request{DstAddr: *dst}).Action == appctlpb.EgressAction_REJECT {
		return errors.New("resolved destination rejected by egress policy")
	}
	return nil
}

func checkPacketDestination(dst *model.AddrSpec, policies []destinationPolicy) error {
	for _, policy := range policies {
		if err := policy(dst); err != nil {
			RejectByRules.Add(1)
			return err
		}
	}
	return nil
}

func checkedForwardPacket(packet []byte, policies []destinationPolicy) ([]byte, error) {
	datagram, err := parseSocks5UDPDatagram(packet)
	if err != nil {
		return nil, err
	}
	if err := checkPacketDestination(&datagram.Addr, policies); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Write([]byte{0, 0, 0})
	if err := datagram.Addr.WriteToSocks5(&out); err != nil {
		return nil, err
	}
	out.Write(datagram.Payload)
	return out.Bytes(), nil
}

func (s *Server) checkConnectRequest(req *model.Request) error {
	if req.Command != constant.Socks5ConnectCmd {
		return nil // An association's address is not its packets' destination.
	}
	if err := s.checkDestination(&req.DstAddr); err != nil {
		return err
	}
	var raw bytes.Buffer
	if err := req.WriteToSocks5(&raw); err != nil {
		return err
	}
	req.Raw = raw.Bytes()
	return nil
}

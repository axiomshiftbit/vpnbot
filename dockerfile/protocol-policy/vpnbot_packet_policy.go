// SPDX-License-Identifier: GPL-3.0-or-later
// VPNBot: enforce destination restrictions on every packet of a UDP association.
package route

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type restrictedPacketConn struct {
	// Do not expose Upstream / ReaderReplaceable: fast copy must not bypass
	// ReadPacket, even when the underlying transport supports unwrapping.
	N.PacketConn
	check func(M.Socksaddr) (M.Socksaddr, error)
}

// Expose buffer requirements without exposing the underlying reader/writer.
// Otherwise the reply path allocates zero headroom and sing-mux/UoT can panic
// when prepending a packet header. Unwrapping would bypass destination checks.
func (c *restrictedPacketConn) FrontHeadroom() int {
	return N.CalculateFrontHeadroom(c.PacketConn)
}

func (c *restrictedPacketConn) RearHeadroom() int {
	return N.CalculateRearHeadroom(c.PacketConn)
}

func (c *restrictedPacketConn) ReaderOverhead() int {
	return N.CalculateReaderOverhead(c.PacketConn)
}

func (c *restrictedPacketConn) ReaderMTU() int {
	return N.CalculateMTU(c.PacketConn, nil)
}

func (c *restrictedPacketConn) WriterMTU() int {
	return N.CalculateMTU(nil, c.PacketConn)
}

func (c *restrictedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		destination, err := c.PacketConn.ReadPacket(buffer)
		if err != nil {
			return destination, err
		}
		checked, err := c.check(destination)
		if err == nil {
			return checked, nil
		}
		// Drop this packet, preserving the association for allowed destinations.
		buffer.Truncate(0)
	}
}

func (r *Router) restrictPackets(ctx context.Context, conn N.PacketConn, base adapter.InboundContext) N.PacketConn {
	return &restrictedPacketConn{PacketConn: conn, check: func(destination M.Socksaddr) (M.Socksaddr, error) {
		return r.checkPacketDestination(ctx, base, destination)
	}}
}

func (r *Router) checkPacketDestination(ctx context.Context, base adapter.InboundContext, destination M.Socksaddr) (M.Socksaddr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Retain the authenticated source/user, but discard cached destination
	// matches from the first packet. VPNBot generates resolve/reject rules
	// and a single selected egress; this never switches WARP to DIRECT.
	metadata := adapter.InboundContext{
		Inbound: base.Inbound, InboundType: base.InboundType, Network: N.NetworkUDP,
		Source: base.Source, User: base.User, Destination: destination.Unwrap(),
	}
	for _, rule := range r.rules {
		metadata.ResetRuleCache()
		if !rule.Match(&metadata) {
			continue
		}
		switch action := rule.Action().(type) {
		case *R.RuleActionResolve:
			if err := r.actionResolve(ctx, &metadata, action); err != nil {
				return M.Socksaddr{}, err
			}
		case *R.RuleActionReject:
			return M.Socksaddr{}, errors.New("UDP destination rejected")
		}
	}
	if metadata.Destination.IsDomain() {
		if len(metadata.DestinationAddresses) == 0 {
			return M.Socksaddr{}, errors.New("UDP destination unresolved")
		}
		address := metadata.DestinationAddresses[0]
		for _, candidate := range metadata.DestinationAddresses {
			if candidate.Is4() {
				address = candidate
				break
			}
		}
		// Pin the actual checked address, including forwarding through SOCKS.
		metadata.Destination = M.Socksaddr{Addr: address.Unmap(), Port: destination.Port}
	}
	if !metadata.Destination.Addr.IsValid() {
		return M.Socksaddr{}, errors.New("invalid UDP destination")
	}
	return metadata.Destination, nil
}

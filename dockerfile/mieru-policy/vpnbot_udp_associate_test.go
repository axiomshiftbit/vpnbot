// SPDX-License-Identifier: GPL-3.0-or-later
package socks5

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
)

// The 3.39.0 buffer reuse must preserve both cached destination headers and
// the VPNBot rule that unsolicited datagrams never enter an association.
func TestVPNBotUDPAssociateBufferReuseAndUnsolicitedSender(t *testing.T) {
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	relay, destination, stranger := listen(), listen(), listen()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	resolver := &changingResolver{ips: []net.IP{net.IPv4(127, 0, 0, 1)}}
	done := make(chan error, 1)
	go func() {
		done <- RunUDPAssociateLoop(relay, common.NewPacketOverStreamTunnel(server), resolver)
	}()
	tunnel := common.NewPacketOverStreamTunnel(client)
	buf := make([]byte, 1<<16)
	for i, size := range []int{1, 32768, 65000, 2} {
		name := fmt.Sprintf("%d.%s.test", i, strings.Repeat("a", 50))
		addr := model.AddrSpec{FQDN: name, Port: destination.LocalAddr().(*net.UDPAddr).Port}
		var request bytes.Buffer
		request.Write([]byte{0, 0, 0})
		if err := addr.WriteToSocks5(&request); err != nil {
			t.Fatal(err)
		}
		header := append([]byte(nil), request.Bytes()...)
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		request.Write(payload)
		if _, err := tunnel.Write(request.Bytes()); err != nil {
			t.Fatal(err)
		}
		destination.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := destination.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatal("outbound UDP changed", err)
		}
		// Multiple replies reuse the cached header and scratch buffer.
		for _, reply := range [][]byte{payload, []byte("small reply")} {
			if _, err := destination.WriteToUDP(reply, from); err != nil {
				t.Fatal(err)
			}
			n, err = tunnel.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], append(append([]byte(nil), header...), reply...)) {
				t.Fatal("cached header or UDP reply changed", err)
			}
		}
	}
	if _, err := stranger.WriteToUDP([]byte("unsolicited"), relay.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := tunnel.Read(buf); err == nil {
		t.Fatal("unsolicited UDP sender accepted")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal("association failed before unsolicited-packet timeout", err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association did not stop with client")
	}
}

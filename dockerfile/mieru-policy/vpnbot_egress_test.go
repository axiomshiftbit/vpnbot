// SPDX-License-Identifier: GPL-3.0-or-later
package socks5

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
)

func TestVPNBotUDPForwardingDoesNotAdvertiseEgressIPToClient(t *testing.T) {
	downstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer downstream.Close()
	server, client := net.Pipe()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	control, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	for _, c := range []net.Conn{server, client, control, peer} {
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	negotiated := make(chan error, 1)
	go func() {
		_, err := model.ReadSocks5Request(peer)
		if err == nil {
			addr := downstream.LocalAddr().(*net.UDPAddr)
			err = model.WriteSocks5Response(peer, constant.Socks5ReplySuccess, model.AddrSpec{IP: addr.IP, Port: addr.Port})
		}
		negotiated <- err
	}()
	s := &Server{config: &Config{}}
	done := make(chan error, 1)
	go func() { done <- s.handleForwardingUDP(&model.Request{}, server, control) }()
	response, err := model.ReadSocks5Response(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-negotiated; err != nil {
		t.Fatal(err)
	}
	// The native client rewrites this port to its local UDP listener. Passing
	// the downstream proxy's IP would send application datagrams to WARP
	// directly, using the client's port instead of the proxy's relay port.
	if len(response.Raw) != 10 || response.Raw[3] != 1 || !bytes.Equal(response.Raw[4:8], []byte{0, 0, 0, 0}) {
		t.Fatal("Mieru association advertised the downstream SOCKS address", response.Raw)
	}
	var packet bytes.Buffer
	packet.Write([]byte{0, 0, 0})
	addr := model.AddrSpec{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	if err := addr.WriteToSocks5(&packet); err != nil {
		t.Fatal(err)
	}
	packet.WriteString("controlled UDP payload")
	tunnel := common.NewPacketOverStreamTunnel(client)
	if _, err := tunnel.Write(packet.Bytes()); err != nil {
		t.Fatal(err)
	}
	downstream.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, source, err := downstream.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], packet.Bytes()) {
		t.Fatal("UDP did not reach downstream proxy", err)
	}
	if _, err := downstream.WriteToUDP(buf[:n], source); err != nil {
		t.Fatal(err)
	}
	if n, err := tunnel.Read(buf); err != nil || !bytes.Equal(buf[:n], packet.Bytes()) {
		t.Fatal("UDP reply did not return through Mieru", err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association did not stop with client")
	}
}

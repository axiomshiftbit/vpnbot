package anytls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestVPNBotFallbackFixedWebsite(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host == "attacker.invalid" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Error("client supplied the upstream host")
		}
		io.WriteString(w, "own website "+r.URL.Path)
	}))
	defer origin.Close()
	f := newVPNBotFallback(strings.TrimPrefix(origin.URL, "https://"), "")
	transport := f.proxy.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	transport.TLSClientConfig.RootCAs = pool
	for _, target := range []string{"/page", "http://attacker.invalid/page"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "attacker.invalid"
		r.Header.Set("X-Forwarded-Host", "attacker.invalid")
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "own website /page" {
			t.Fatal("website was not served")
		}
	}
	w := httptest.NewRecorder()
	f.ServeHTTP(w, httptest.NewRequest("CONNECT", "http://attacker.invalid:443", nil))
	if w.Code != 405 || calls.Load() != 2 {
		t.Fatal("CONNECT reached upstream")
	}
}

func TestVPNBotFallbackRejectsUntrustedTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted origin reached") }))
	defer origin.Close()
	f := newVPNBotFallback(strings.TrimPrefix(origin.URL, "https://"), "")
	defer f.proxy.Transport.(*http.Transport).CloseIdleConnections()
	w := httptest.NewRecorder()
	f.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 502 {
		t.Fatal("untrusted certificate accepted")
	}
	if strings.Contains(w.Body.String(), "certificate") {
		t.Fatal("internal error exposed")
	}
}

func TestVPNBotFallbackConnectionLifecycle(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "website") }))
	defer origin.Close()
	f := newVPNBotFallback(strings.TrimPrefix(origin.URL, "https://"), "")
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	f.proxy.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	defer f.proxy.Transport.(*http.Transport).CloseIdleConnections()
	for _, cancelEarly := range []bool{false, true} {
		server, client := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var closed atomic.Int32
		go func() {
			f.NewConnectionEx(ctx, server, M.Socksaddr{}, M.Socksaddr{}, func(error) { closed.Add(1) })
			close(done)
		}()
		client.SetDeadline(time.Now().Add(3 * time.Second))
		if !cancelEarly {
			io.WriteString(client, "GET / HTTP/1.1\r\nHost: cover.example\r\nConnection: close\r\n\r\n")
			r, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != 200 || string(body) != "website" {
				t.Fatal("HTTP over fallback connection failed")
			}
		}
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("fallback goroutine leaked")
		}
		if closed.Load() != 1 || len(f.slots) != 0 {
			t.Fatal("callback or slot leaked")
		}
	}
}

func TestVPNBotFallbackConnectionLimit(t *testing.T) {
	f := newVPNBotFallback("website.example", "")
	for i := 0; i < cap(f.slots); i++ {
		f.slots <- struct{}{}
	}
	a, b := net.Pipe()
	defer b.Close()
	var closed atomic.Int32
	f.NewConnectionEx(context.Background(), a, M.Socksaddr{}, M.Socksaddr{}, func(error) { closed.Add(1) })
	if closed.Load() != 1 {
		t.Fatal("over-limit connection retained")
	}
	if _, err := b.Write([]byte("test")); err == nil {
		t.Fatal("over-limit connection open")
	}
}

func TestVPNBotFallbackInternalTLSStillChecksWebsiteName(t *testing.T) {
	var hostname string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != hostname || r.Host != hostname {
			t.Error("website SNI or Host lost on internal route")
		}
		io.WriteString(w, "internal website")
	}))
	defer origin.Close()
	hostname = origin.Certificate().DNSNames[0]
	for _, valid := range []bool{true, false} {
		name := hostname
		if !valid {
			name = "wrong.example.test"
		}
		f := newVPNBotFallback(name, origin.Listener.Addr().String())
		pool := x509.NewCertPool()
		pool.AddCert(origin.Certificate())
		transport := f.proxy.Transport.(*http.Transport)
		transport.TLSClientConfig.RootCAs = pool
		w := httptest.NewRecorder()
		f.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		transport.CloseIdleConnections()
		expected := 502
		if valid {
			expected = 200
		}
		if w.Code != expected {
			t.Fatalf("certificate name validation: got %d, want %d", w.Code, expected)
		}
	}
}

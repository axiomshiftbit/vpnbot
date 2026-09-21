package anytls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The protocol library supplies the original, unauthenticated plaintext here.
// It can reach only the configured HTTPS website, never a client-selected proxy.
type vpnBotFallback struct {
	proxy *httputil.ReverseProxy
	slots chan struct{}
}

func newVPNBotFallback(host string, address string) *vpnBotFallback {
	target := &url.URL{Scheme: "https", Host: host}
	dial := (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	if address != "" {
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		}
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dial,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConnsPerHost:   4,
			MaxConnsPerHost:       32,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return &vpnBotFallback{
		slots: make(chan struct{}, 32),
		proxy: proxy,
	}
}

func (f *vpnBotFallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	f.proxy.ServeHTTP(w, r)
}

func (f *vpnBotFallback) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	default:
		conn.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	l := &vpnBotSingleListener{done: make(chan struct{}), conn: conn}
	defer l.Close()
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()
	s := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	stop := context.AfterFunc(ctx, func() { s.Close(); l.Close() })
	defer stop()
	_ = s.Serve(l)
}

type vpnBotSingleListener struct {
	conn     net.Conn
	done     chan struct{}
	once     sync.Once
	accepted bool
}

func (l *vpnBotSingleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return &vpnBotFallbackConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *vpnBotSingleListener) Close() error {
	l.once.Do(func() { l.conn.Close(); close(l.done) })
	return nil
}
func (l *vpnBotSingleListener) Addr() net.Addr { return l.conn.LocalAddr() }

type vpnBotFallbackConn struct {
	net.Conn
	listener *vpnBotSingleListener
}

func (c *vpnBotFallbackConn) Close() error { return c.listener.Close() }

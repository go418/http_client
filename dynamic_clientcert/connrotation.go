// Package connrotation implements a connection dialer that tracks and can close
// all created connections.
//
// This is used for credential rotation of long-lived connections, when there's
// no way to re-authenticate on a live connection.
package dynamic_clientcert

import (
	"context"
	"net"
	"sync"
)

// DialContextFunc is a shorthand for signature of net.DialContext.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer opens connections through Dial and tracks them.
type dialer struct {
	dial  DialContextFunc
	conns map[*closableConn]struct{}
	mu    sync.Mutex
}

// NewDialer creates a new Dialer instance.
// Equivalent to NewDialerWithTracker(dial, nil).
func NewDialer(dialContext DialContextFunc) *dialer {
	return &dialer{
		dial:  dialContext,
		conns: make(map[*closableConn]struct{}),
	}
}

// CloseAll forcibly closes all tracked connections.
//
// Note: new connections may get created before CloseAll returns.
func (c *dialer) CloseAll() {
	c.mu.Lock()
	conns := c.conns
	c.conns = make(map[*closableConn]struct{})
	c.mu.Unlock()

	for conn := range conns {
		conn.Conn.Close()
	}
}

// Track adds the connection to the list of tracked connections,
// and returns a wrapped copy of the connection that stops tracking the connection
// when it is closed.
func (c *dialer) track(conn net.Conn) net.Conn {
	closable := &closableConn{Conn: conn}

	// When the connection is closed, remove it from the map. This will
	// be no-op if the connection isn't in the map, e.g. if CloseAll()
	// is called.
	closable.onClose = func() {
		c.mu.Lock()
		delete(c.conns, closable)
		c.mu.Unlock()
	}

	// Start tracking the connection
	c.mu.Lock()
	c.conns[closable] = struct{}{}
	c.mu.Unlock()

	return closable
}

// Dial creates a new tracked connection.
func (d *dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext creates a new tracked connection.
func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return d.track(conn), nil
}

type closableConn struct {
	onClose func()
	net.Conn
}

func (c *closableConn) Close() error {
	c.onClose()
	return c.Conn.Close()
}

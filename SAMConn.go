package sam3

import (
	"net"
	"time"

	"github.com/go-i2p/i2pkeys"
)

// SAMConn sets up a SAM connection.
// Implements net.Conn
type SAMConn struct {
	laddr i2pkeys.I2PAddr
	raddr i2pkeys.I2PAddr
	net.Conn
}

// Read implements net.Conn
func (sc *SAMConn) Read(buf []byte) (int, error) {
	n, err := sc.Conn.Read(buf)
	return n, err
}

// Write Implements net.Conn
func (sc *SAMConn) Write(buf []byte) (int, error) {
	n, err := sc.Conn.Write(buf)
	return n, err
}

// Close Implements net.Conn
func (sc *SAMConn) Close() error {
	return sc.Conn.Close()
}

// LocalAddr Implements net.Conn
func (sc *SAMConn) LocalAddr() net.Addr {
	return sc.localAddr()
}

func (sc *SAMConn) localAddr() i2pkeys.I2PAddr {
	return sc.laddr
}

// RemoteAddr Implements net.Conn
func (sc *SAMConn) RemoteAddr() net.Addr {
	return sc.remoteAddr()
}

func (sc *SAMConn) remoteAddr() i2pkeys.I2PAddr {
	return sc.raddr
}

// SetDeadline Implements net.Conn
func (sc *SAMConn) SetDeadline(t time.Time) error {
	return sc.Conn.SetDeadline(t)
}

// SetReadDeadline Implements net.Conn
func (sc *SAMConn) SetReadDeadline(t time.Time) error {
	return sc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline Implements net.Conn
func (sc *SAMConn) SetWriteDeadline(t time.Time) error {
	return sc.Conn.SetWriteDeadline(t)
}

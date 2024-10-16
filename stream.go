package sam3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"strings"
	"time"

	"github.com/eyedeekay/i2pkeys"
)

// Represents a streaming session.
type StreamSession struct {
	samAddr  string          // address to the sam bridge (ipv4:port)
	id       string          // tunnel name
	conn     net.Conn        // connection to sam
	keys     i2pkeys.I2PKeys // i2p destination keys
	Timeout  time.Duration
	Deadline time.Time
	sigType  string
	from     string
	to       string
}

func (s *StreamSession) SetDeadline(t time.Time) error {
	log.WithField("deadline", t).Debug("Setting deadline for StreamSession")
	return s.conn.SetDeadline(t)
}

func (s *StreamSession) SetReadDeadline(t time.Time) error {
	log.WithField("readDeadline", t).Debug("Setting read deadline for StreamSession")
	return s.conn.SetReadDeadline(t)
}

func (s *StreamSession) SetWriteDeadline(t time.Time) error {
	log.WithField("writeDeadline", t).Debug("Setting write deadline for StreamSession")
	return s.conn.SetWriteDeadline(t)
}

func (ss *StreamSession) From() string {
	return ss.from
}

func (ss *StreamSession) To() string {
	return ss.to
}

func (ss *StreamSession) SignatureType() string {
	return ss.sigType
}

// Returns the local tunnel name of the I2P tunnel used for the stream session
func (ss *StreamSession) ID() string {
	return ss.id
}

func (ss *StreamSession) Close() error {
	log.WithField("id", ss.id).Info("Closing StreamSession")
	return ss.conn.Close()
}

// Returns the I2P destination (the address) of the stream session
func (ss *StreamSession) Addr() i2pkeys.I2PAddr {
	return ss.keys.Addr()
}

func (ss *StreamSession) LocalAddr() net.Addr {
	return ss.keys.Addr()
}

// Returns the keys associated with the stream session
func (ss *StreamSession) Keys() i2pkeys.I2PKeys {
	return ss.keys
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewStreamSession(id string, keys i2pkeys.I2PKeys, options []string) (*StreamSession, error) {
	log.WithFields(logrus.Fields{"id": id, "options": options}).Debug("Creating new StreamSession")
	conn, err := sam.newGenericSession("STREAM", id, keys, options, []string{})
	if err != nil {
		return nil, err
	}
	log.WithField("id", id).Info("Created new StreamSession")
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, "0", "0"}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewStreamSessionWithSignature(id string, keys i2pkeys.I2PKeys, options []string, sigType string) (*StreamSession, error) {
	log.WithFields(logrus.Fields{"id": id, "options": options, "sigType": sigType}).Debug("Creating new StreamSession with signature")
	conn, err := sam.newGenericSessionWithSignature("STREAM", id, keys, sigType, options, []string{})
	if err != nil {
		return nil, err
	}
	log.WithFields(logrus.Fields{"id": id, "sigType": sigType}).Info("Created new StreamSession with signature")
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, keys, time.Duration(600 * time.Second), time.Now(), sigType, "0", "0"}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewStreamSessionWithSignatureAndPorts(id, from, to string, keys i2pkeys.I2PKeys, options []string, sigType string) (*StreamSession, error) {
	log.WithFields(logrus.Fields{"id": id, "from": from, "to": to, "options": options, "sigType": sigType}).Debug("Creating new StreamSession with signature and ports")
	conn, err := sam.newGenericSessionWithSignatureAndPorts("STREAM", id, from, to, keys, sigType, options, []string{})
	if err != nil {
		return nil, err
	}
	log.WithFields(logrus.Fields{"id": id, "from": from, "to": to, "sigType": sigType}).Info("Created new StreamSession with signature and ports")
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, keys, time.Duration(600 * time.Second), time.Now(), sigType, from, to}, nil
}

// lookup name, convenience function
func (s *StreamSession) Lookup(name string) (i2pkeys.I2PAddr, error) {
	log.WithField("name", name).Debug("Looking up address")
	sam, err := NewSAM(s.samAddr)
	if err == nil {
		addr, err := sam.Lookup(name)
		defer sam.Close()
		if err != nil {
			log.WithError(err).Error("Lookup failed")
		} else {
			log.WithField("addr", addr).Debug("Lookup successful")
		}
		return addr, err
	}
	log.WithError(err).Error("Failed to create SAM instance for lookup")
	return i2pkeys.I2PAddr(""), err
}

// context-aware dialer, eventually...
func (s *StreamSession) DialContext(ctx context.Context, n, addr string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"network": n, "addr": addr}).Debug("DialContext called")
	return s.DialContextI2P(ctx, n, addr)
}

// context-aware dialer, eventually...
func (s *StreamSession) DialContextI2P(ctx context.Context, n, addr string) (*SAMConn, error) {
	log.WithFields(logrus.Fields{"network": n, "addr": addr}).Debug("DialContextI2P called")
	if ctx == nil {
		log.Panic("nil context")
		panic("nil context")
	}
	deadline := s.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	i2paddr, err := i2pkeys.NewI2PAddrFromString(addr)
	if err != nil {
		log.WithError(err).Error("Failed to create I2P address from string")
		return nil, err
	}
	return s.DialI2P(i2paddr)
}

/*
func (s *StreamSession) Cancel() chan *StreamSession {
	ch := make(chan *StreamSession)
	ch <- s
	return ch
}*/

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (s *StreamSession) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if s.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(s.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, s.Deadline)
}

// implement net.Dialer
func (s *StreamSession) Dial(n, addr string) (c net.Conn, err error) {
	log.WithFields(logrus.Fields{"network": n, "addr": addr}).Debug("Dial called")

	var i2paddr i2pkeys.I2PAddr
	var host string
	host, _, err = SplitHostPort(addr)
	//log.Println("Dialing:", host)
	if err = IgnorePortError(err); err == nil {
		// check for name
		if strings.HasSuffix(host, ".b32.i2p") || strings.HasSuffix(host, ".i2p") {
			// name lookup
			i2paddr, err = s.Lookup(host)
			log.WithFields(logrus.Fields{"host": host, "i2paddr": i2paddr}).Debug("Looked up I2P address")
		} else {
			// probably a destination
			i2paddr, err = i2pkeys.NewI2PAddrFromBytes([]byte(host))
			//i2paddr = i2pkeys.I2PAddr(host)
			//log.Println("Destination:", i2paddr, err)
			log.WithFields(logrus.Fields{"host": host, "i2paddr": i2paddr}).Debug("Created I2P address from bytes")
		}
		if err == nil {
			return s.DialI2P(i2paddr)
		}
	}
	log.WithError(err).Error("Dial failed")
	return
}

// Dials to an I2P destination and returns a SAMConn, which implements a net.Conn.
func (s *StreamSession) DialI2P(addr i2pkeys.I2PAddr) (*SAMConn, error) {
	log.WithField("addr", addr).Debug("DialI2P called")
	sam, err := NewSAM(s.samAddr)
	if err != nil {
		log.WithError(err).Error("Failed to create new SAM instance")
		return nil, err
	}
	conn := sam.conn
	_, err = conn.Write([]byte("STREAM CONNECT ID=" + s.id + " FROM_PORT=" + s.from + " TO_PORT=" + s.to + " DESTINATION=" + addr.Base64() + " SILENT=false\n"))
	if err != nil {
		log.WithError(err).Error("Failed to write STREAM CONNECT command")
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.WithError(err).Error("Failed to write STREAM CONNECT command")
		conn.Close()
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(buf[:n]))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		switch scanner.Text() {
		case "STREAM":
			continue
		case "STATUS":
			continue
		case "RESULT=OK":
			log.Debug("Successfully connected to I2P destination")
			return &SAMConn{s.keys.Addr(), addr, conn}, nil
		case "RESULT=CANT_REACH_PEER":
			log.Error("Can't reach peer")
			conn.Close()
			return nil, errors.New("Can not reach peer")
		case "RESULT=I2P_ERROR":
			log.Error("I2P internal error")
			conn.Close()
			return nil, errors.New("I2P internal error")
		case "RESULT=INVALID_KEY":
			log.Error("Invalid key - Stream Session")
			conn.Close()
			return nil, errors.New("Invalid key - Stream Session")
		case "RESULT=INVALID_ID":
			log.Error("Invalid tunnel ID")
			conn.Close()
			return nil, errors.New("Invalid tunnel ID")
		case "RESULT=TIMEOUT":
			log.Error("Connection timeout")
			conn.Close()
			return nil, errors.New("Timeout")
		default:
			log.WithField("error", scanner.Text()).Error("Unknown error")
			conn.Close()
			return nil, errors.New("Unknown error: " + scanner.Text() + " : " + string(buf[:n]))
		}
	}
	log.Panic("Unexpected end of StreamSession.DialI2P()")
	panic("sam3 go library error in StreamSession.DialI2P()")
}

// create a new stream listener to accept inbound connections
func (s *StreamSession) Listen() (*StreamListener, error) {
	log.WithFields(logrus.Fields{"id": s.id, "laddr": s.keys.Addr()}).Debug("Creating new StreamListener")
	return &StreamListener{
		session: s,
		id:      s.id,
		laddr:   s.keys.Addr(),
	}, nil
}

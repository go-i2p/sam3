package sam3

import (
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
)

// The RawSession provides no authentication of senders, and there is no sender
// address attached to datagrams, so all communication is anonymous. The
// messages send are however still endpoint-to-endpoint encrypted. You
// need to figure out a way to identify and authenticate clients yourself, iff
// that is needed. Raw datagrams may be at most 32 kB in size. There is no
// overhead of authentication, which is the reason to use this..
type RawSession struct {
	samAddr  string          // address to the sam bridge (ipv4:port)
	id       string          // tunnel name
	conn     net.Conn        // connection to sam bridge
	udpconn  *net.UDPConn    // used to deliver datagrams
	keys     i2pkeys.I2PKeys // i2p destination keys
	rUDPAddr *net.UDPAddr    // the SAM bridge UDP-port
}

// Creates a new raw session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *SAM) NewRawSession(id string, keys i2pkeys.I2PKeys, options []string, udpPort int) (*RawSession, error) {
	log.WithFields(logrus.Fields{"id": id, "udpPort": udpPort}).Debug("Creating new RawSession")

	if udpPort > 65335 || udpPort < 0 {
		log.WithField("udpPort", udpPort).Error("Invalid UDP port")
		return nil, errors.New("udpPort needs to be in the interval 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
		log.Debug("Using default UDP port 7655")
	}
	lhost, _, err := SplitHostPort(s.conn.LocalAddr().String())
	if err != nil {
		log.Debug("Using default UDP port 7655")
		s.Close()
		return nil, err
	}
	lUDPAddr, err := net.ResolveUDPAddr("udp4", lhost+":0")
	if err != nil {
		log.WithError(err).Error("Failed to resolve local UDP address")
		return nil, err
	}
	udpconn, err := net.ListenUDP("udp4", lUDPAddr)
	if err != nil {
		log.WithError(err).Error("Failed to listen on UDP")
		return nil, err
	}
	rhost, _, err := SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to split remote host port")
		s.Close()
		return nil, err
	}
	rUDPAddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(udpPort))
	if err != nil {
		log.WithError(err).Error("Failed to resolve remote UDP address")
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to get local port")
		return nil, err
	}
	conn, err := s.newGenericSession("RAW", id, keys, options, []string{"PORT=" + lport})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic session")
		return nil, err
	}
	log.WithFields(logrus.Fields{
		"id":            id,
		"localPort":     lport,
		"remoteUDPAddr": rUDPAddr,
	}).Debug("Created new RawSession")

	return &RawSession{s.SAMEmit.I2PConfig.Sam(), id, conn, udpconn, keys, rUDPAddr}, nil
}

// Read one raw datagram sent to the destination of the DatagramSession. Returns
// the number of bytes read. Who sent the raw message can not be determined at
// this layer - you need to do it (in a secure way!).
func (s *RawSession) Read(b []byte) (n int, err error) {
	log.Debug("Attempting to read raw datagram")
	for {
		var saddr *net.UDPAddr
		n, saddr, err = s.udpconn.ReadFromUDP(b)
		if err != nil {
			log.WithError(err).Error("Failed to read from UDP")
			return 0, err
		}

		// Verify source is SAM bridge
		if saddr.IP.Equal(s.rUDPAddr.IP) && saddr.Port == s.rUDPAddr.Port {
			log.WithField("bytesRead", n).Debug("Successfully read raw datagram")
			return n, nil
		}

		// Log unexpected source
		log.Printf("Ignored datagram from unauthorized source: %v", saddr)
		continue
	}
}

// Sends one raw datagram to the destination specified. At the time of writing,
// maximum size is 32 kilobyte, but this may change in the future.
func (s *RawSession) WriteTo(b []byte, addr i2pkeys.I2PAddr) (n int, err error) {
	log.WithFields(logrus.Fields{
		"destAddr": addr.String(),
		"dataLen":  len(b),
	}).Debug("Attempting to write raw datagram")

	header := []byte("3.0 " + s.id + " " + addr.String() + "\n")
	msg := append(header, b...)
	n, err = s.udpconn.WriteToUDP(msg, s.rUDPAddr)
	if err != nil {
		log.WithError(err).Error("Failed to write to UDP")
	}
	log.WithField("bytesWritten", n).Debug("Successfully wrote raw datagram")
	return n, err
}

// Closes the RawSession.
func (s *RawSession) Close() error {
	log.Debug("Closing RawSession")

	err := s.conn.Close()
	if err != nil {
		log.WithError(err).Error("Failed to close connection")
		return err
	}

	err2 := s.udpconn.Close()
	if err2 != nil {
		log.WithError(err2).Error("Failed to close UDP connection")
	}

	log.Debug("RawSession closed")
	return err2
}

// Returns the local I2P destination of the RawSession.
func (s *RawSession) LocalAddr() i2pkeys.I2PAddr {
	return s.keys.Addr()
}

func (s *RawSession) SetDeadline(t time.Time) error {
	return s.udpconn.SetDeadline(t)
}

func (s *RawSession) SetReadDeadline(t time.Time) error {
	return s.udpconn.SetReadDeadline(t)
}

func (s *RawSession) SetWriteDeadline(t time.Time) error {
	return s.udpconn.SetWriteDeadline(t)
}

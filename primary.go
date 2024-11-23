package sam3

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
)

const (
	session_ADDOK = "SESSION STATUS RESULT=OK"
)

func randport() string {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	p := r.Intn(55534) + 10000
	port := strconv.Itoa(p)
	log.WithField("port", port).Debug("Generated random port")
	return strconv.Itoa(p)
}

// Represents a primary session.
type PrimarySession struct {
	samAddr  string          // address to the sam bridge (ipv4:port)
	id       string          // tunnel name
	conn     net.Conn        // connection to sam
	keys     i2pkeys.I2PKeys // i2p destination keys
	Timeout  time.Duration
	Deadline time.Time
	sigType  string
	Config   SAMEmit
	stsess   map[string]*StreamSession
	dgsess   map[string]*DatagramSession
	sync.RWMutex
	//	from     string
	//	to       string
}

func (ss *PrimarySession) From() string {
	return "0"
}

func (ss *PrimarySession) To() string {
	return "0"
}

func (ss *PrimarySession) SignatureType() string {
	return ss.sigType
}

// Returns the local tunnel name of the I2P tunnel used for the stream session
func (ss *PrimarySession) ID() string {
	return ss.id
}

func (ss *PrimarySession) Close() error {
	return ss.conn.Close()
}

// Returns the I2P destination (the address) of the stream session
func (ss *PrimarySession) Addr() i2pkeys.I2PAddr {
	return ss.keys.Addr()
}

func (ss *PrimarySession) LocalAddr() net.Addr {
	aa := ss.keys.Addr()
	return &aa
}

// Returns the keys associated with the stream session
func (ss *PrimarySession) Keys() i2pkeys.I2PKeys {
	return ss.keys
}

func (sam *PrimarySession) Dial(network, addr string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"network": network, "addr": addr}).Debug("Dial() called")
	if network == "udp" || network == "udp4" || network == "udp6" {
		// return sam.DialUDPI2P(network, network+addr[0:4], addr)
		return sam.DialUDPI2P(network, network+addr[0:4], addr)
	}
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		// return sam.DialTCPI2P(network, network+addr[0:4], addr)
		return sam.DialTCPI2P(network, network+addr[0:4], addr)
	}
	log.WithField("network", network).Error("Invalid network type")
	return nil, fmt.Errorf("Error: Must specify a valid network type")
}

// DialTCP implements x/dialer
func (sam *PrimarySession) DialTCP(network string, laddr, raddr net.Addr) (net.Conn, error) {
	log.WithFields(logrus.Fields{"network": network, "laddr": laddr, "raddr": raddr}).Debug("DialTCP() called")
	sam.RLock()
	ts, ok := sam.stsess[network+raddr.String()[0:4]]
	sam.RUnlock()

	if !ok {
		sam.Lock()
		ts, err := sam.NewUniqueStreamSubSession(network + raddr.String()[0:4])
		if err != nil {
			log.WithError(err).Error("Failed to create new unique stream sub-session")
			sam.Unlock()
			return nil, err
		}
		sam.stsess[network+raddr.String()[0:4]] = ts
		sam.Unlock()
	}
	return ts.Dial(network, raddr.String())
}

func (sam *PrimarySession) DialTCPI2P(network, laddr, raddr string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"network": network, "laddr": laddr, "raddr": raddr}).Debug("DialTCPI2P() called")
	sam.RLock()
	ts, ok := sam.stsess[network+raddr[0:4]]
	sam.RUnlock()
	if !ok {
		sam.Lock()
		ts, err := sam.NewUniqueStreamSubSession(network + laddr)
		if err != nil {
			log.WithError(err).Error("Failed to create new unique stream sub-session")
			sam.Unlock()
			return nil, err
		}
		sam.stsess[network+raddr[0:4]] = ts
		sam.Unlock()
	}
	return ts.Dial(network, raddr)
}

// DialUDP implements x/dialer
func (sam *PrimarySession) DialUDP(network string, laddr, raddr net.Addr) (net.PacketConn, error) {
	log.WithFields(logrus.Fields{"network": network, "laddr": laddr, "raddr": raddr}).Debug("DialUDP() called")
	sam.RLock()
	ds, ok := sam.dgsess[network+raddr.String()[0:4]]
	sam.RUnlock()
	if !ok {
		sam.Lock()
		ds, err := sam.NewDatagramSubSession(network+raddr.String()[0:4], 0)
		if err != nil {
			log.WithError(err).Error("Failed to create new datagram sub-session")
			sam.Unlock()
			return nil, err
		}
		sam.dgsess[network+raddr.String()[0:4]] = ds
		sam.Unlock()
	}
	return ds.Dial(network, raddr.String())
}

func (sam *PrimarySession) DialUDPI2P(network, laddr, raddr string) (*DatagramSession, error) {
	log.WithFields(logrus.Fields{"network": network, "laddr": laddr, "raddr": raddr}).Debug("DialUDPI2P() called")
	sam.RLock()
	ds, ok := sam.dgsess[network+raddr[0:4]]
	sam.RUnlock()
	if !ok {
		sam.Lock()
		ds, err := sam.NewDatagramSubSession(network+laddr, 0)
		if err != nil {
			log.WithError(err).Error("Failed to create new datagram sub-session")
			sam.Unlock()
			return nil, err
		}
		sam.dgsess[network+raddr[0:4]] = ds
		sam.Unlock()
	}
	return ds.Dial(network, raddr)
}

func (s *PrimarySession) Lookup(name string) (a net.Addr, err error) {
	log.WithField("name", name).Debug("Lookup() called")
	var sam *SAM
	name = strings.Split(name, ":")[0]
	sam, err = NewSAM(s.samAddr)
	if err == nil {
		log.WithField("addr", a).Debug("Lookup successful")
		defer sam.Close()
		a, err = sam.Lookup(name)
	}
	log.WithError(err).Error("Lookup failed")
	return
}

func (sam *PrimarySession) Resolve(network, addr string) (net.Addr, error) {
	log.WithFields(logrus.Fields{"network": network, "addr": addr}).Debug("Resolve() called")
	return sam.Lookup(addr)
}

func (sam *PrimarySession) ResolveTCPAddr(network, dest string) (net.Addr, error) {
	log.WithFields(logrus.Fields{"network": network, "dest": dest}).Debug("ResolveTCPAddr() called")
	return sam.Lookup(dest)
}

func (sam *PrimarySession) ResolveUDPAddr(network, dest string) (net.Addr, error) {
	log.WithFields(logrus.Fields{"network": network, "dest": dest}).Debug("ResolveUDPAddr() called")
	return sam.Lookup(dest)
}

// Creates a new PrimarySession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewPrimarySession(id string, keys i2pkeys.I2PKeys, options []string) (*PrimarySession, error) {
	log.WithFields(logrus.Fields{"id": id, "options": options}).Debug("NewPrimarySession() called")
	return sam.newPrimarySession(PrimarySessionSwitch, id, keys, options)
}

func (sam *SAM) newPrimarySession(primarySessionSwitch, id string, keys i2pkeys.I2PKeys, options []string) (*PrimarySession, error) {
	log.WithFields(logrus.Fields{
		"primarySessionSwitch": primarySessionSwitch,
		"id":                   id,
		"options":              options,
	}).Debug("newPrimarySession() called")

	conn, err := sam.newGenericSession(primarySessionSwitch, id, keys, options, []string{})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic session")
		return nil, err
	}
	ssesss := make(map[string]*StreamSession)
	dsesss := make(map[string]*DatagramSession)
	return &PrimarySession{
		samAddr:  sam.Config.I2PConfig.Sam(),
		id:       id,
		conn:     conn,
		keys:     keys,
		Timeout:  time.Duration(600 * time.Second),
		Deadline: time.Now(),
		sigType:  Sig_NONE,
		Config:   sam.Config,
		stsess:   ssesss,
		dgsess:   dsesss,
		RWMutex:  sync.RWMutex{},
	}, nil
}

// Creates a new PrimarySession with the I2CP- and PRIMARYinglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewPrimarySessionWithSignature(id string, keys i2pkeys.I2PKeys, options []string, sigType string) (*PrimarySession, error) {
	log.WithFields(logrus.Fields{
		"id":      id,
		"options": options,
		"sigType": sigType,
	}).Debug("NewPrimarySessionWithSignature() called")

	conn, err := sam.newGenericSessionWithSignature(PrimarySessionSwitch, id, keys, sigType, options, []string{})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic session with signature")
		return nil, err
	}
	ssesss := make(map[string]*StreamSession)
	dsesss := make(map[string]*DatagramSession)
	return &PrimarySession{
		samAddr:  sam.Config.I2PConfig.Sam(),
		id:       id,
		conn:     conn,
		keys:     keys,
		Timeout:  time.Duration(600 * time.Second),
		Deadline: time.Now(),
		sigType:  sigType,
		Config:   sam.Config,
		stsess:   ssesss,
		dgsess:   dsesss,
		RWMutex:  sync.RWMutex{},
	}, nil
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *PrimarySession) newGenericSubSession(style, id string, extras []string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"style": style, "id": id, "extras": extras}).Debug("newGenericSubSession called")
	return sam.newGenericSubSessionWithSignature(style, id, extras)
}

func (sam *PrimarySession) newGenericSubSessionWithSignature(style, id string, extras []string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"style": style, "id": id, "extras": extras}).Debug("newGenericSubSessionWithSignature called")
	return sam.newGenericSubSessionWithSignatureAndPorts(style, id, "0", "0", extras)
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *PrimarySession) newGenericSubSessionWithSignatureAndPorts(style, id, from, to string, extras []string) (net.Conn, error) {
	log.WithFields(logrus.Fields{"style": style, "id": id, "from": from, "to": to, "extras": extras}).Debug("newGenericSubSessionWithSignatureAndPorts called")

	conn := sam.conn
	fp := ""
	tp := ""
	if from != "0" && from != "" {
		fp = " FROM_PORT=" + from
	}
	if to != "0" && to != "" {
		tp = " TO_PORT=" + to
	}
	scmsg := []byte("SESSION ADD STYLE=" + style + " ID=" + id + fp + tp + " " + strings.Join(extras, " ") + "\n")

	log.WithField("message", string(scmsg)).Debug("Sending SESSION ADD message")

	for m, i := 0, 0; m != len(scmsg); i++ {
		if i == 15 {
			conn.Close()
			log.Error("Writing to SAM failed after 15 attempts")
			return nil, errors.New("writing to SAM failed")
		}
		n, err := conn.Write(scmsg[m:])
		if err != nil {
			log.WithError(err).Error("Failed to write to SAM connection")
			conn.Close()
			return nil, err
		}
		m += n
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.WithError(err).Error("Failed to read from SAM connection")
		conn.Close()
		return nil, err
	}
	text := string(buf[:n])
	log.WithField("response", text).Debug("Received response from SAM")
	// log.Println("SAM:", text)
	if strings.HasPrefix(text, session_ADDOK) {
		//if sam.keys.String() != text[len(session_ADDOK):len(text)-1] {
		//conn.Close()
		//return nil, errors.New("SAMv3 created a tunnel with keys other than the ones we asked it for")
		//}
		log.Debug("Session added successfully")
		return conn, nil //&StreamSession{id, conn, keys, nil, sync.RWMutex{}, nil}, nil
	} else if text == session_DUPLICATE_ID {
		log.Error("Duplicate tunnel name")
		conn.Close()
		return nil, errors.New("Duplicate tunnel name")
	} else if text == session_DUPLICATE_DEST {
		log.Error("Duplicate destination")
		conn.Close()
		return nil, errors.New("Duplicate destination")
	} else if text == session_INVALID_KEY {
		log.Error("Invalid key - Primary Session")
		conn.Close()
		return nil, errors.New("Invalid key - Primary Session")
	} else if strings.HasPrefix(text, session_I2P_ERROR) {
		log.WithField("error", text[len(session_I2P_ERROR):]).Error("I2P error")
		conn.Close()
		return nil, errors.New("I2P error " + text[len(session_I2P_ERROR):])
	} else {
		log.WithField("reply", text).Error("Unable to parse SAMv3 reply")
		conn.Close()
		return nil, errors.New("Unable to parse SAMv3 reply: " + text)
	}
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewStreamSubSession(id string) (*StreamSession, error) {
	log.WithField("id", id).Debug("NewStreamSubSession called")
	conn, err := sam.newGenericSubSession("STREAM", id, []string{})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic sub-session")
		return nil, err
	}
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, "0", "0"}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewUniqueStreamSubSession(id string) (*StreamSession, error) {
	log.WithField("id", id).Debug("NewUniqueStreamSubSession called")
	conn, err := sam.newGenericSubSession("STREAM", id, []string{})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic sub-session")
		return nil, err
	}
	fromPort, toPort := randport(), randport()
	log.WithFields(logrus.Fields{"fromPort": fromPort, "toPort": toPort}).Debug("Generated random ports")
	// return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, randport(), randport()}, nil
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, fromPort, toPort}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewStreamSubSessionWithPorts(id, from, to string) (*StreamSession, error) {
	log.WithFields(logrus.Fields{"id": id, "from": from, "to": to}).Debug("NewStreamSubSessionWithPorts called")
	conn, err := sam.newGenericSubSessionWithSignatureAndPorts("STREAM", id, from, to, []string{})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic sub-session with signature and ports")
		return nil, err
	}
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, from, to}, nil
}

/*
func (s *PrimarySession) I2PListener(name string) (*StreamListener, error) {
	listener, err := s.NewStreamSubSession(name)
	if err != nil {
		return nil, err
	}
	return listener.Listen()
}
*/

// Creates a new datagram session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *PrimarySession) NewDatagramSubSession(id string, udpPort int, datagramOptions ...DatagramOptions) (*DatagramSession, error) {
	log.WithFields(logrus.Fields{"id": id, "udpPort": udpPort}).Debug("NewDatagramSubSession called")
	if udpPort > 65335 || udpPort < 0 {
		log.WithField("udpPort", udpPort).Error("Invalid UDP port")
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
		log.Debug("Using default UDP port 7655")
	}
	lhost, _, err := SplitHostPort(s.conn.LocalAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to split local host port")
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
		s.Close()
		return nil, err
	}
	conn, err := s.newGenericSubSession("DATAGRAM", id, []string{"PORT=" + lport})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic sub-session")
		return nil, err
	}
	if len(datagramOptions) > 0 {
		return &DatagramSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, s.keys, rUDPAddr, nil, &datagramOptions[0]}, nil
	}
	opts := &DatagramOptions{
		SendTags:     0,
		TagThreshold: 0,
		Expires:      0,
		SendLeaseset: false,
	}
	log.WithFields(logrus.Fields{"id": id, "localPort": lport}).Debug("Created new datagram sub-session")
	return &DatagramSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, s.keys, rUDPAddr, nil, opts}, nil
}

// Creates a new raw session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *PrimarySession) NewRawSubSession(id string, udpPort int) (*RawSession, error) {
	log.WithFields(logrus.Fields{"id": id, "udpPort": udpPort}).Debug("NewRawSubSession called")

	if udpPort > 65335 || udpPort < 0 {
		log.WithField("udpPort", udpPort).Error("Invalid UDP port")
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
		log.Debug("Using default UDP port 7655")
	}
	lhost, _, err := SplitHostPort(s.conn.LocalAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to split local host port")
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
		s.Close()
		return nil, err
	}
	//	conn, err := s.newGenericSubSession("RAW", id, s.keys, options, []string{"PORT=" + lport})
	conn, err := s.newGenericSubSession("RAW", id, []string{"PORT=" + lport})
	if err != nil {
		log.WithError(err).Error("Failed to create new generic sub-session")
		return nil, err
	}

	log.WithFields(logrus.Fields{"id": id, "localPort": lport}).Debug("Created new raw sub-session")
	return &RawSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, s.keys, rUDPAddr}, nil
}

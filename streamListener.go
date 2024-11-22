package sam3

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
)

type StreamListener struct {
	// parent stream session
	session *StreamSession
	// our session id
	id string
	// our local address for this sam socket
	laddr i2pkeys.I2PAddr
}

func (l *StreamListener) From() string {
	return l.session.from
}

func (l *StreamListener) To() string {
	return l.session.to
}

// get our address
// implements net.Listener
func (l *StreamListener) Addr() net.Addr {
	return l.laddr
}

// implements net.Listener
func (l *StreamListener) Close() error {
	return l.session.Close()
}

// implements net.Listener
func (l *StreamListener) Accept() (net.Conn, error) {
	return l.AcceptI2P()
}

func ExtractPairString(input, value string) string {
	log.WithFields(logrus.Fields{"input": input, "value": value}).Debug("ExtractPairString called")
	parts := strings.Split(input, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, value) {
			kv := strings.SplitN(input, "=", 2)
			if len(kv) == 2 {
				log.WithFields(logrus.Fields{"key": kv[0], "value": kv[1]}).Debug("Pair extracted")
				return kv[1]
			}
		}
	}
	log.WithFields(logrus.Fields{"input": input, "value": value}).Debug("No pair found")
	return ""
}

func ExtractPairInt(input, value string) int {
	rv, err := strconv.Atoi(ExtractPairString(input, value))
	if err != nil {
		log.WithFields(logrus.Fields{"input": input, "value": value}).Debug("No pair found")
		return 0
	}
	log.WithField("result", rv).Debug("Pair extracted and converted to int")
	return rv
}

func ExtractDest(input string) string {
	log.WithField("input", input).Debug("ExtractDest called")
	dest := strings.Split(input, " ")[0]
	log.WithField("dest", dest).Debug("Destination extracted")
	return strings.Split(input, " ")[0]
}

// accept a new inbound connection
func (l *StreamListener) AcceptI2P() (*SAMConn, error) {
	log.Debug("StreamListener.AcceptI2P() called")
	s, err := NewSAM(l.session.samAddr)
	if err == nil {
		log.Debug("Connected to SAM bridge")
		// we connected to sam
		// send accept() command
		_, err = io.WriteString(s.conn, "STREAM ACCEPT ID="+l.id+" SILENT=false\n")
		if err != nil {
			log.WithError(err).Error("Failed to send STREAM ACCEPT command")
			s.Close()
			return nil, err
		}
		// read reply
		rd := bufio.NewReader(s.conn)
		// read first line
		line, err := rd.ReadString(10)
		if err != nil {
			log.WithError(err).Error("Failed to read SAM bridge response")
			s.Close()
			return nil, err
		}
		log.WithField("response", line).Debug("Received SAM bridge response")
		log.Println(line)
		if strings.HasPrefix(line, "STREAM STATUS RESULT=OK") {
			// we gud read destination line
			destline, err := rd.ReadString(10)
			if err == nil {
				dest := ExtractDest(destline)
				l.session.from = ExtractPairString(destline, "FROM_PORT")
				l.session.to = ExtractPairString(destline, "TO_PORT")
				// return wrapped connection
				dest = strings.Trim(dest, "\n")
				log.WithFields(logrus.Fields{
					"dest": dest,
					"from": l.session.from,
					"to":   l.session.to,
				}).Debug("Accepted new I2P connection")
				return &SAMConn{
					laddr: l.laddr,
					raddr: i2pkeys.I2PAddr(dest),
					conn:  s.conn,
				}, nil
			} else {
				log.WithError(err).Error("Failed to read destination line")
				s.Close()
				return nil, err
			}
		} else {
			log.WithField("line", line).Error("Invalid SAM response")
			s.Close()
			return nil, errors.New("invalid sam line: " + line)
		}
	} else {
		log.WithError(err).Error("Failed to connect to SAM bridge")
		s.Close()
		return nil, err
	}
}

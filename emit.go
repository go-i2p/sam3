package sam3

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

type SAMEmit struct {
	I2PConfig
}

func (e *SAMEmit) OptStr() string {
	optStr := strings.Join(e.I2PConfig.Print(), " ")
	log.WithField("optStr", optStr).Debug("Generated option string")
	return optStr
}

func (e *SAMEmit) Hello() string {
	hello := fmt.Sprintf("HELLO VERSION MIN=%s MAX=%s \n", e.I2PConfig.MinSAM(), e.I2PConfig.MaxSAM())
	log.WithField("hello", hello).Debug("Generated HELLO command")
	return hello
}

func (e *SAMEmit) HelloBytes() []byte {
	return []byte(e.Hello())
}

func (e *SAMEmit) GenerateDestination() string {
	dest := fmt.Sprintf("DEST GENERATE %s \n", e.I2PConfig.SignatureType())
	log.WithField("destination", dest).Debug("Generated DEST GENERATE command")
	return dest
}

func (e *SAMEmit) GenerateDestinationBytes() []byte {
	return []byte(e.GenerateDestination())
}

func (e *SAMEmit) Lookup(name string) string {
	lookup := fmt.Sprintf("NAMING LOOKUP NAME=%s \n", name)
	log.WithField("lookup", lookup).Debug("Generated NAMING LOOKUP command")
	return lookup
}

func (e *SAMEmit) LookupBytes(name string) []byte {
	return []byte(e.Lookup(name))
}

func (e *SAMEmit) Connect(dest string) string {
	connect := fmt.Sprintf(
		"STREAM CONNECT ID=%s %s %s DESTINATION=%s \n",
		e.I2PConfig.ID(),
		e.I2PConfig.FromPort(),
		e.I2PConfig.ToPort(),
		dest,
	)
	log.WithField("connect", connect).Debug("Generated STREAM CONNECT command")
	return connect
}

func (e *SAMEmit) ConnectBytes(dest string) []byte {
	return []byte(e.Connect(dest))
}

func (e *SAMEmit) Accept() string {
	accept := fmt.Sprintf(
		"STREAM ACCEPT ID=%s %s %s",
		e.I2PConfig.ID(),
		e.I2PConfig.FromPort(),
		e.I2PConfig.ToPort(),
	)
	log.WithField("accept", accept).Debug("Generated STREAM ACCEPT command")
	return accept
}

func (e *SAMEmit) AcceptBytes() []byte {
	return []byte(e.Accept())
}

func NewEmit(opts ...func(*SAMEmit) error) (*SAMEmit, error) {
	var emit SAMEmit
	for _, o := range opts {
		if err := o(&emit); err != nil {
			log.WithError(err).Error("Failed to apply option")
			return nil, err
		}
	}
	log.Debug("New SAMEmit instance created")
	return &emit, nil
}

func IgnorePortError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "missing port in address") {
		log.Debug("Ignoring 'missing port in address' error")
		err = nil
	}
	return err
}

func SplitHostPort(hostport string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if IgnorePortError(err) == nil {
			log.WithField("host", hostport).Debug("Using full string as host, port set to 0")
			host = hostport
			port = "0"
		}
	}
	log.WithFields(logrus.Fields{
		"host": host,
		"port": port,
	}).Debug("Split host and port")
	return host, port, nil
}

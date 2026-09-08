package sam3

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/sam3/common"
	"github.com/go-i2p/sam3/config"
)

const DEFAULT_LEASESET_TYPE = "i2cp.leaseSetEncType=4"

// I2PConfig is a struct which manages I2P configuration options
type I2PConfig struct {
	common.SAMFormatter
	config.SessionOptions
	config.TransportOptions
	config.TunnelOptions
	config.EncryptedLeaseSetOptions
	DestinationKeys i2pkeys.I2PKeys

	// Streaming Library options
	AccessListType string
	AccessList     []string
}

// Sam returns the SAM address in the form of "host:port"
func (f *I2PConfig) Sam() string {
	host := "127.0.0.1"
	port := "7656"
	if f.SamHost != "" {
		host = f.SamHost
	}
	if f.SamPort != "" {
		port = f.SamPort
	}
	log.WithFields(logrus.Fields{
		"host": host,
		"port": port,
	}).Debug("SAM address constructed")
	return fmt.Sprintf("%s:%s", host, port)
}

// SetSAMAddress sets the SAM address from a string in the form of "host:port"
func (f *I2PConfig) SetSAMAddress(addr string) {
	hp := strings.Split(addr, ":")
	if len(hp) == 1 {
		f.SamHost = hp[0]
	} else if len(hp) == 2 {
		f.SamPort = hp[1]
		f.SamHost = hp[0]
	} else {
		if f.SamHost == "" {
			f.SamHost = "127.0.0.1"
		}
		if f.SamPort == "" {
			f.SamPort = "7656"
		}
	}
	log.WithFields(logrus.Fields{
		"host": f.SamHost,
		"port": f.SamPort,
	}).Debug("SAM address set")
	i2pkeys.DefaultSAMAddress = f.Sam()
}

// ID returns the tunnel name in the form of "ID=name"
func (f *I2PConfig) ID() string {
	if f.NickName == "" {
		b := make([]byte, 12)
		for i := range b {
			b[i] = "abcdefghijklmnopqrstuvwxyz"[rand.Intn(len("abcdefghijklmnopqrstuvwxyz"))]
		}
		f.NickName = string(b)
		log.WithField("NickName", f.NickName).Debug("Generated random tunnel name")
	}
	return fmt.Sprintf(" ID=%s ", f.NickName)
}

// MinSAM returns the minimum SAM version required in major.minor form
func (f *I2PConfig) MinSAM() string {
	min, _ := f.GetVersions()
	return string(min)
}

// MaxSAM returns the maximum SAM version required in major.minor form
func (f *I2PConfig) MaxSAM() string {
	_, max := f.GetVersions()
	return string(max)
}

func (f *I2PConfig) GetVersions() (min, max common.ProtocolVersion) {
	if f.SamMin == "" {
		min = common.SAM31Version.String
	} else {
		min = common.ProtocolVersion(f.SamMin)
	}
	if f.SamMax == "" {
		max = common.SAM33Version.String
		log.Debug("Using default MaxSAM: 3.3")
	} else {
		max = common.ProtocolVersion(f.SamMax)
	}
	return min, max
}

// DestinationKey returns the destination key setting in the form of "DESTINATION=key"
func (f *I2PConfig) DestinationKey() string {
	if &f.DestinationKeys != nil {
		log.WithField("destinationKey", f.DestinationKeys.String()).Debug("Destination key set")
		fmt.Sprintf(" DESTINATION=%s ", f.DestinationKeys.String())
	}
	log.Debug("Using TRANSIENT destination")
	return " DESTINATION=TRANSIENT "
}

// Print returns the full config as a string
func (f *I2PConfig) Print() []string {
	lsk, lspk, lspsk := f.Leasesetsettings()
	return []string{
		// f.targetForPort443(),
		f.InboundLength(),
		f.OutboundLength(),
		f.InboundVariance(),
		f.OutboundVariance(),
		f.InboundBackupQuantity(),
		f.OutboundBackupQuantity(),
		f.InboundQuantity(),
		f.OutboundQuantity(),
		f.InboundDoZero(),
		f.OutboundDoZero(),
		//"i2cp.fastRecieve=" + f.FastRecieve,
		f.DoFastReceive(),
		f.UsesCompression(),
		f.Reduce(),
		f.Close(),
		f.Reliability(),
		f.EncryptLease(),
		lsk, lspk, lspsk,
		f.Accesslisttype(),
		f.Accesslist(),
		f.LeaseSetEncryptionType(),
	}
}

// Accesslisttype returns the access list type
func (f *I2PConfig) Accesslisttype() string {
	if f.AccessListType == "whitelist" {
		log.Debug("Access list type set to whitelist")
		return "i2cp.enableAccessList=true"
	} else if f.AccessListType == "blacklist" {
		log.Debug("Access list type set to blacklist")
		return "i2cp.enableBlackList=true"
	} else if f.AccessListType == "none" {
		log.Debug("Access list type set to none")
		return ""
	}
	log.Debug("Access list type not set")
	return ""
}

// Accesslist returns the access list in the form of "i2cp.accessList=list"
func (f *I2PConfig) Accesslist() string {
	if f.AccessListType != "" && len(f.AccessList) > 0 {
		r := strings.Join(f.AccessList, ",")
		log.WithField("accessList", r).Debug("Access list generated")
		return fmt.Sprintf(" i2cp.accessList=%s ", r)
	}
	log.Debug("Access list not set")
	return ""
}

// NewConfig returns a new config with default values or updates them with functional arguments
func NewConfig(opts ...func(*I2PConfig) error) (*I2PConfig, error) {
	config := I2PConfig{
		EncryptedLeaseSetOptions: config.EncryptedLeaseSetOptions{
			EncryptLeaseSet:           false,
			LeaseSetKey:               "",
			LeaseSetPrivateKey:        "",
			LeaseSetPrivateSigningKey: "",
			LeaseSetEncryption:        DEFAULT_LEASESET_TYPE,
		},
		TunnelOptions: config.TunnelOptions{
			InAllowZeroHop:    false,
			OutAllowZeroHop:   false,
			InLength:          3,
			OutLength:         3,
			InQuantity:        2,
			OutQuantity:       2,
			InVariance:        1,
			OutVariance:       1,
			InBackupQuantity:  3,
			OutBackupQuantity: 3,
		},
		SessionOptions: config.SessionOptions{
			NickName:   "",
			Style:      "STREAM",
			SigType:    "EdDSA_SHA512_Ed25519",
			InFromPort: "",
			OutToPort:  "",
			Protocol:   "",
			UDPPort:    0,
			SamHost:    "127.0.0.1",
			SamPort:    "7656",
			SamMin:     string(common.SAM31Version.String),
			SamMax:     string(common.SAM33Version.String),
		},
		TransportOptions: config.TransportOptions{
			UseCompression:     "true",
			FastReceive:        "false",
			MessageReliability: "none",
			CloseIdleTimeout:   5 * time.Minute,
			ReduceIdleQuantity: 1,
			ReduceIdle:         false,
			CloseIdle:          false,
		},
	}
	for _, o := range opts {
		if err := o(&config); err != nil {
			return nil, err
		}
	}
	return &config, nil
}

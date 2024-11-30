package sam3

import (
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
	return host + ":" + port
}

// SetSAMAddress sets the SAM address from a string in the form of "host:port"
func (f *I2PConfig) SetSAMAddress(addr string) {
	hp := strings.Split(addr, ":")
	if len(hp) == 1 {
		f.SamHost = hp[0]
	} else if len(hp) == 2 {
		f.SamPort = hp[1]
		f.SamHost = hp[0]
	}
	f.SamPort = "7656"
	f.SamHost = "127.0.0.1"
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
	return " ID=" + f.NickName + " "
}

// Leasesetsettings returns the lease set settings in the form of "i2cp.leaseSetKey=key i2cp.leaseSetPrivateKey=key i2cp.leaseSetPrivateSigningKey=key"
func (f *I2PConfig) Leasesetsettings() (string, string, string) {
	var r, s, t string
	if f.LeaseSetKey != "" {
		r = " i2cp.leaseSetKey=" + f.LeaseSetKey + " "
	}
	if f.LeaseSetPrivateKey != "" {
		s = " i2cp.leaseSetPrivateKey=" + f.LeaseSetPrivateKey + " "
	}
	if f.LeaseSetPrivateSigningKey != "" {
		t = " i2cp.leaseSetPrivateSigningKey=" + f.LeaseSetPrivateSigningKey + " "
	}
	log.WithFields(logrus.Fields{
		"leaseSetKey":               r,
		"leaseSetPrivateKey":        s,
		"leaseSetPrivateSigningKey": t,
	}).Debug("Lease set settings constructed")
	return r, s, t
}

// SessionStyle returns the session style setting in the form of "STYLE=style"
func (f *I2PConfig) SessionStyle() string {
	if f.SessionOptions.Style != "" {
		log.WithField("style", f.SessionOptions.Style).Debug("Session style set")
		return " STYLE=" + f.SessionOptions.Style + " "
	}
	log.Debug("Using default STREAM style")
	return " STYLE=STREAM "
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
		return " DESTINATION=" + f.DestinationKeys.String() + " "
	}
	log.Debug("Using TRANSIENT destination")
	return " DESTINATION=TRANSIENT "
}

// Reliability returns the message reliability setting in the form of "i2cp.messageReliability=reliability"
func (f *I2PConfig) Reliability() string {
	if f.TransportOptions.Reliability != "" {
		log.WithField("reliability", f.TransportOptions.Reliability).Debug("Message reliability set")
		return " i2cp.messageReliability=" + f.TransportOptions.Reliability + " "
	}
	log.Debug("Message reliability not set")
	return ""
}

// Reduce returns the reduce idle settings in the form of "i2cp.reduceOnIdle=true i2cp.reduceIdleTime=time i2cp.reduceQuantity=quantity"
func (f *I2PConfig) Reduce() string {
	if f.ReduceIdle {
		log.WithFields(logrus.Fields{
			"reduceIdle":         f.ReduceIdle,
			"reduceIdleTime":     f.TransportOptions.ReduceIdleTimeout.String(),
			"reduceIdleQuantity": f.TransportOptions.ReduceIdleQuantity,
		}).Debug("Reduce idle settings applied")
		return "i2cp.reduceOnIdle=" + f.ReduceOnIdle() + "i2cp.reduceIdleTime=" + f.TransportOptions.ReduceIdleTimeout.String() + "i2cp.reduceQuantity=" + f.ReduceQuantity()
	}
	log.Debug("Reduce idle settings not applied")
	return ""
}

// Close returns the close idle settings in the form of "i2cp.closeOnIdle=true i2cp.closeIdleTime=time"
func (f *I2PConfig) Close() string {
	if f.CloseIdle {
		log.WithFields(logrus.Fields{
			"closeIdle":     f.CloseIdle,
			"closeIdleTime": f.TransportOptions.CloseIdleTimeout.String(),
		}).Debug("Close idle settings applied")
		return "i2cp.closeOnIdle=" + f.CloseOnIdle() + "i2cp.closeIdleTime=" + f.TransportOptions.CloseIdleTimeout.String()
	}
	log.Debug("Close idle settings not applied")
	return ""
}

// Print returns the full config as a string
func (f *I2PConfig) Print() []string {
	lsk, lspk, lspsk := f.Leasesetsettings()
	return []string{
		// f.targetForPort443(),
		"inbound.length=" + f.InboundLength(),
		"outbound.length=" + f.OutboundLength(),
		"inbound.lengthVariance=" + f.InboundVariance(),
		"outbound.lengthVariance=" + f.OutboundVariance(),
		"inbound.backupQuantity=" + f.InboundBackupQuantity(),
		"outbound.backupQuantity=" + f.OutboundBackupQuantity(),
		"inbound.quantity=" + f.InboundQuantity(),
		"outbound.quantity=" + f.OutboundQuantity(),
		f.DoZero(),
		//"i2cp.fastRecieve=" + f.FastRecieve,
		"i2cp.gzip=" + f.TransportOptions.UseCompression,
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
		r := ""
		for _, s := range f.AccessList {
			r += s + ","
		}
		log.WithField("accessList", r).Debug("Access list generated")
		return "i2cp.accessList=" + strings.TrimSuffix(r, ",")
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
			Reliability:        "none",
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

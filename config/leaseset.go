package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-i2p/i2pkeys"
	"github.com/sirupsen/logrus"
)

type EncryptedLeaseSetOptions struct {
	EncryptLeaseSet           bool
	LeaseSetKey               string
	LeaseSetPrivateKey        string
	LeaseSetPrivateSigningKey string
	LeaseSetKeys              i2pkeys.I2PKeys
	LeaseSetEncryption        string
}

// EncryptLease returns the lease set encryption setting in the form of "i2cp.encryptLeaseSet=true"
func (f *EncryptedLeaseSetOptions) EncryptLease() string {
	if f.EncryptLeaseSet {
		log.Debug("Lease set encryption enabled")
		return " i2cp.encryptLeaseSet=true "
	}
	log.Debug("Lease set encryption not enabled")
	return ""
}

// LeaseSetEncryptionType returns the lease set encryption type in the form of "i2cp.leaseSetEncType=type"
func (f *EncryptedLeaseSetOptions) LeaseSetEncryptionType() string {
	if f.LeaseSetEncryption == "" {
		log.Debug("Using default lease set encryption type: 4,0")
		return "i2cp.leaseSetEncType=4,0"
	}
	for _, s := range strings.Split(f.LeaseSetEncryption, ",") {
		if _, err := strconv.Atoi(s); err != nil {
			log.WithField("invalidType", s).Panic("Invalid encrypted leaseSet type")
			// panic("Invalid encrypted leaseSet type: " + s)
		}
	}
	log.WithField("leaseSetEncType", f.LeaseSetEncryption).Debug("Lease set encryption type set")
	return fmt.Sprintf(" i2cp.leaseSetEncType=%s ", f.LeaseSetEncryption)
}

func (f *EncryptedLeaseSetOptions) leaseSetKey() string {
	if f.LeaseSetKey != "" {
		return fmt.Sprintf(" i2cp.leaseSetKey=%s ", f.LeaseSetKey)
	}
	return ""
}

func (f *EncryptedLeaseSetOptions) leaseSetPrivateKey() string {
	if f.LeaseSetPrivateKey != "" {
		return fmt.Sprintf(" i2cp.leaseSetPrivateKey=%s ", f.LeaseSetPrivateKey)
	}
	return ""
}

func (f *EncryptedLeaseSetOptions) leaseSetPrivateSigningKey() string {
	if f.LeaseSetPrivateSigningKey != "" {
		return fmt.Sprintf(" i2cp.leaseSetPrivateSigningKey=%s ", f.LeaseSetPrivateSigningKey)
	}
	return ""
}

// Leasesetsettings returns the lease set settings in the form of "i2cp.leaseSetKey=key i2cp.leaseSetPrivateKey=key i2cp.leaseSetPrivateSigningKey=key"
func (f *EncryptedLeaseSetOptions) Leasesetsettings() (string, string, string) {
	if f.EncryptLeaseSet {
		var r, s, t string
		r = f.leaseSetKey()
		s = f.leaseSetPrivateKey()
		t = f.leaseSetPrivateSigningKey()
		log.WithFields(logrus.Fields{
			"leaseSetKey":               r,
			"leaseSetPrivateKey":        s,
			"leaseSetPrivateSigningKey": t,
		}).Debug("Lease set settings constructed")
		return r, s, t
	}
	return "", "", ""
}

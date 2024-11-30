package config

import (
	"strconv"
	"strings"

	"github.com/go-i2p/i2pkeys"
)

type EncryptedLeaseSetOptions struct {
	// SigType                   string
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
	return "i2cp.leaseSetEncType=" + f.LeaseSetEncryption
}

package config

import (
	"fmt"
	"strconv"

	"github.com/go-i2p/sam3/common"
)

type SessionOptions struct {
	NickName   string
	Style      string
	SigType    string
	InFromPort string
	OutToPort  string
	Protocol   string
	UDPPort    int
	SamHost    string
	SamPort    string
	SamMin     string
	SamMax     string
}

func (f *SessionOptions) samMax() float64 {
	i, err := strconv.Atoi(f.SamMax)
	if err != nil {
		log.WithError(err).Warn("Failed to parse SamMax, using default 3.1")
		return 3.1
	}
	log.WithField("samMax", float64(i)).Debug("SAM max version parsed")
	return float64(i)
}

// SignatureType returns the signature type setting in the form of "SIGNATURE_TYPE=type"
func (f *SessionOptions) SignatureType() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, SignatureType not applicable")
		return ""
	}
	if f.SigType != "" {
		log.WithField("sigType", f.SigType).Debug("Signature type set")
		return fmt.Sprintf(" SIGNATURE_TYPE=%s ", f.SigType)
	}
	log.Debug("Signature type not set")
	return ""
}

// FromPort returns the from port setting in the form of "FROM_PORT=port"
func (f *SessionOptions) FromPort() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, FromPort not applicable")
		return ""
	}
	if f.InFromPort != "0" {
		log.WithField("fromPort", f.InFromPort).Debug("FromPort set")
		return fmt.Sprintf(" FROM_PORT=%s ", f.InFromPort)
	}
	log.Debug("FromPort not set")
	return ""
}

// ToPort returns the to port setting in the form of "TO_PORT=port"
func (f *SessionOptions) ToPort() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, ToPort not applicable")
		return ""
	}
	if f.OutToPort != "0" {
		log.WithField("toPort", f.OutToPort).Debug("ToPort set")
		return fmt.Sprintf(" TO_PORT=%s ", f.OutToPort)
	}
	log.Debug("ToPort not set")
	return ""
}

// SessionStyle returns the session style setting in the form of "STYLE=style"
func (f *SessionOptions) SessionStyle() string {
	if f.Style != "" {
		log.WithField("style", f.Style).Debug("Session style set")
		return fmt.Sprintf(" STYLE=%s ", f.Style)
	}
	log.Debug("Using default STREAM style")
	return " STYLE=STREAM "
}

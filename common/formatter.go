package common

import (
	"fmt"
	"strings"
)

type SAMFormatter struct {
	Version ProtocolVersion
}

// Common SAM protocol message types
const (
	HelloMsg    = "HELLO"
	SessionMsg  = "SESSION"
	StreamMsg   = "STREAM"
	DatagramMsg = "DATAGRAM"
	RawMsg      = "RAW"
	PrimaryMSG  = "PRIMARY"
	NamingMsg   = "NAMING"
)

func NewSAMFormatter(version ProtocolVersion) *SAMFormatter {
	return &SAMFormatter{Version: version}
}

// FormatHello formats the initial handshake message
func (f *SAMFormatter) FormatHello() string {
	return fmt.Sprintf("HELLO VERSION MIN=%s MAX=%s\n", f.Version, f.Version)
}

// FormatSession formats a session creation message
func (f *SAMFormatter) FormatSession(style, id string, options map[string]string) string {
	optStr := formatOptions(options)
	return fmt.Sprintf("SESSION CREATE STYLE=%s ID=%s%s\n", style, id, optStr)
}

// FormatDatagram formats a datagram message
func (f *SAMFormatter) FormatDatagram(sessionID, dest string, options map[string]string) string {
	optStr := formatOptions(options)
	return fmt.Sprintf("DATAGRAM SEND ID=%s DESTINATION=%s%s\n", sessionID, dest, optStr)
}

// FormatNamingLookup formats a naming lookup message
func (f *SAMFormatter) FormatNamingLookup(name string) string {
	return fmt.Sprintf("NAMING LOOKUP NAME=%s\n", name)
}

// Helper function to format options
func formatOptions(options map[string]string) string {
	if len(options) == 0 {
		return ""
	}

	var opts []string
	for k, v := range options {
		opts = append(opts, fmt.Sprintf(" %s=%s", k, v))
	}
	return strings.Join(opts, "")
}

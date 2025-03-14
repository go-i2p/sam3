package sam3

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
)

// I2PConfig is a struct which manages I2P configuration options
type I2PConfig struct {
	SamHost string
	SamPort string
	TunName string

	SamMin string
	SamMax string

	Fromport string
	Toport   string

	Style   string
	TunType string

	DestinationKeys i2pkeys.I2PKeys

	SigType                   string
	EncryptLeaseSet           string
	LeaseSetKey               string
	LeaseSetPrivateKey        string
	LeaseSetPrivateSigningKey string
	LeaseSetKeys              i2pkeys.I2PKeys
	InAllowZeroHop            string
	OutAllowZeroHop           string
	InLength                  string
	OutLength                 string
	InQuantity                string
	OutQuantity               string
	InVariance                string
	OutVariance               string
	InBackupQuantity          string
	OutBackupQuantity         string
	FastRecieve               string
	UseCompression            string
	MessageReliability        string
	CloseIdle                 string
	CloseIdleTime             string
	ReduceIdle                string
	ReduceIdleTime            string
	ReduceIdleQuantity        string
	LeaseSetEncryption        string

	//Streaming Library options
	AccessListType string
	AccessList     []string
}

// Sam returns the SAM bridge address as a string in the format "host:port"
func (f *I2PConfig) Sam() string {
	// Set default values
	host := "127.0.0.1"
	port := "7656"

	// Override defaults if config values are set
	if f.SamHost != "" {
		host = f.SamHost
	}
	if f.SamPort != "" {
		port = f.SamPort
	}

	// Log the SAM address being constructed
	log.WithFields(logrus.Fields{
		"host": host,
		"port": port,
	}).Debug("SAM address constructed")

	// Return formatted SAM address
	return fmt.Sprintf("%s:%s", host, port)
}

// SetSAMAddress sets the SAM bridge host and port from a combined address string
// addr format can be either "host" or "host:port"
func (f *I2PConfig) SetSAMAddress(addr string) {
	// Split address into host and port components
	hp := strings.Split(addr, ":")

	// If only host provided, set just the host
	if len(hp) == 1 {
		f.SamHost = hp[0]
	} else if len(hp) == 2 { // If host:port provided, set both
		f.SamPort = hp[1]
		f.SamHost = hp[0]
	}

	// Set default values
	f.SamPort = "7656"
	f.SamHost = "127.0.0.1"

	// Log the configured SAM address
	log.WithFields(logrus.Fields{
		"host": f.SamHost,
		"port": f.SamPort,
	}).Debug("SAM address set")
}

// ID returns the tunnel name as a formatted string. If no tunnel name is set,
// generates a random 12-character name using lowercase letters.
func (f *I2PConfig) ID() string {
	// If no tunnel name set, generate random one
	if f.TunName == "" {
		// Generate 12 random lowercase letters
		b := make([]byte, 12)
		for i := range b {
			b[i] = "abcdefghijklmnopqrstuvwxyz"[rand.Intn(26)]
		}
		f.TunName = string(b)

		// Log the generated name
		log.WithField("TunName", f.TunName).Debug("Generated random tunnel name")
	}

	// Return formatted ID string
	return fmt.Sprintf(" ID=%s ", f.TunName)
}

// Leasesetsettings returns the lease set configuration strings for I2P
// Returns three strings: lease set key, private key, and private signing key settings
func (f *I2PConfig) Leasesetsettings() (string, string, string) {
	// Initialize empty strings for each setting
	var leaseSetKey, privateKey, privateSigningKey string

	// Set lease set key if configured
	if f.LeaseSetKey != "" {
		leaseSetKey = fmt.Sprintf(" i2cp.leaseSetKey=%s ", f.LeaseSetKey)
	}

	// Set lease set private key if configured
	if f.LeaseSetPrivateKey != "" {
		privateKey = fmt.Sprintf(" i2cp.leaseSetPrivateKey=%s ", f.LeaseSetPrivateKey)
	}

	// Set lease set private signing key if configured
	if f.LeaseSetPrivateSigningKey != "" {
		privateSigningKey = fmt.Sprintf(" i2cp.leaseSetPrivateSigningKey=%s ", f.LeaseSetPrivateSigningKey)
	}

	// Log the constructed settings
	log.WithFields(logrus.Fields{
		"leaseSetKey":               leaseSetKey,
		"leaseSetPrivateKey":        privateKey,
		"leaseSetPrivateSigningKey": privateSigningKey,
	}).Debug("Lease set settings constructed")

	return leaseSetKey, privateKey, privateSigningKey
}

// FromPort returns the FROM_PORT configuration string for SAM bridges >= 3.1
// Returns an empty string if SAM version < 3.1 or if fromport is "0"
func (f *I2PConfig) FromPort() string {
	// Check SAM version compatibility
	if f.samMax() < 3.1 {
		log.Debug("SAM version < 3.1, FromPort not applicable")
		return ""
	}

	// Return formatted FROM_PORT if fromport is set
	if f.Fromport != "0" {
		log.WithField("fromPort", f.Fromport).Debug("FromPort set")
		return fmt.Sprintf(" FROM_PORT=%s ", f.Fromport)
	}

	log.Debug("FromPort not set")
	return ""
}

// ToPort returns the TO_PORT configuration string for SAM bridges >= 3.1
// Returns an empty string if SAM version < 3.1 or if toport is "0"
func (f *I2PConfig) ToPort() string {
	// Check SAM version compatibility
	if f.samMax() < 3.1 {
		log.Debug("SAM version < 3.1, ToPort not applicable")
		return ""
	}

	// Return formatted TO_PORT if toport is set
	if f.Toport != "0" {
		log.WithField("toPort", f.Toport).Debug("ToPort set")
		return fmt.Sprintf(" TO_PORT=%s ", f.Toport)
	}

	log.Debug("ToPort not set")
	return ""
}

// SessionStyle returns the SAM session style configuration string
// If no style is set, defaults to "STREAM"
func (f *I2PConfig) SessionStyle() string {
	if f.Style != "" {
		// Log custom style setting
		log.WithField("style", f.Style).Debug("Session style set")
		return fmt.Sprintf(" STYLE=%s ", f.Style)
	}

	// Log default style
	log.Debug("Using default STREAM style")
	return " STYLE=STREAM "
}

// samMax returns the maximum SAM version supported as a float64
// If parsing fails, returns default value 3.1
func (f *I2PConfig) samMax() float64 {
	// Parse SAM max version to integer
	i, err := strconv.ParseFloat(f.SamMax, 64)
	if err != nil {
		log.WithError(err).Warn("Failed to parse SamMax, using default 3.1")
		return 3.1
	}

	// Log the parsed version and return
	log.WithField("samMax", i).Debug("SAM max version parsed")
	return i
}

// MinSAM returns the minimum SAM version supported as a string
// If no minimum version is set, returns default value "3.0"
func (f *I2PConfig) MinSAM() string {
	if f.SamMin == "" {
		log.Debug("Using default MinSAM: 3.0")
		return "3.0"
	}
	log.WithField("minSAM", f.SamMin).Debug("MinSAM set")
	return f.SamMin
}

// MaxSAM returns the maximum SAM version supported as a string
// If no maximum version is set, returns default value "3.1"
func (f *I2PConfig) MaxSAM() string {
	if f.SamMax == "" {
		log.Debug("Using default MaxSAM: 3.1")
		return "3.1"
	}
	log.WithField("maxSAM", f.SamMax).Debug("MaxSAM set")
	return f.SamMax
}

// DestinationKey returns the DESTINATION configuration string for the SAM bridge
// If destination keys are set, returns them as a string, otherwise returns "TRANSIENT"
func (f *I2PConfig) DestinationKey() string {
	// Check if destination keys are set
	if &f.DestinationKeys != nil {
		// Log the destination key being used
		log.WithField("destinationKey", f.DestinationKeys.String()).Debug("Destination key set")
		return fmt.Sprintf(" DESTINATION=%s ", f.DestinationKeys.String())
	}

	// Log and return transient destination
	log.Debug("Using TRANSIENT destination")
	return " DESTINATION=TRANSIENT "
}

// SignatureType returns the SIGNATURE_TYPE configuration string for SAM bridges >= 3.1
// Returns empty string if SAM version < 3.1 or if no signature type is set
func (f *I2PConfig) SignatureType() string {
	// Check SAM version compatibility
	if f.samMax() < 3.1 {
		log.Debug("SAM version < 3.1, SignatureType not applicable")
		return ""
	}

	// Return formatted signature type if set
	if f.SigType != "" {
		log.WithField("sigType", f.SigType).Debug("Signature type set")
		return fmt.Sprintf(" SIGNATURE_TYPE=%s ", f.SigType)
	}

	log.Debug("Signature type not set")
	return ""
}

// EncryptLease returns the lease set encryption configuration string
// Returns "i2cp.encryptLeaseSet=true" if encryption is enabled, empty string otherwise
func (f *I2PConfig) EncryptLease() string {
	if f.EncryptLeaseSet == "true" {
		log.Debug("Lease set encryption enabled")
		return fmt.Sprintf(" i2cp.encryptLeaseSet=true ")
	}
	log.Debug("Lease set encryption not enabled")
	return ""
}

// Reliability returns the message reliability configuration string for the SAM bridge
// If a reliability setting is specified, returns formatted i2cp.messageReliability setting
func (f *I2PConfig) Reliability() string {
	if f.MessageReliability != "" {
		// Log the reliability setting being used
		log.WithField("reliability", f.MessageReliability).Debug("Message reliability set")
		return fmt.Sprintf(" i2cp.messageReliability=%s ", f.MessageReliability)
	}

	// Log when reliability is not set
	log.Debug("Message reliability not set")
	return ""
}

// Reduce returns I2CP reduce-on-idle configuration settings as a string if enabled
func (f *I2PConfig) Reduce() string {
	// If reduce idle is enabled, return formatted configuration string
	if f.ReduceIdle == "true" {
		// Log the reduce idle settings being applied
		log.WithFields(logrus.Fields{
			"reduceIdle":         f.ReduceIdle,
			"reduceIdleTime":     f.ReduceIdleTime,
			"reduceIdleQuantity": f.ReduceIdleQuantity,
		}).Debug("Reduce idle settings applied")

		// Return formatted configuration string using Sprintf
		return fmt.Sprintf("i2cp.reduceOnIdle=%s"+
			"i2cp.reduceIdleTime=%s"+
			"i2cp.reduceQuantity=%s",
			f.ReduceIdle,
			f.ReduceIdleTime,
			f.ReduceIdleQuantity)
	}

	// Log when reduce idle is not enabled
	log.Debug("Reduce idle settings not applied")
	return ""
}

// Close returns I2CP close-on-idle configuration settings as a string if enabled
func (f *I2PConfig) Close() string {
	// If close idle is enabled, return formatted configuration string
	if f.CloseIdle == "true" {
		// Log the close idle settings being applied
		log.WithFields(logrus.Fields{
			"closeIdle":     f.CloseIdle,
			"closeIdleTime": f.CloseIdleTime,
		}).Debug("Close idle settings applied")

		// Return formatted configuration string using Sprintf
		return fmt.Sprintf("i2cp.closeOnIdle=%s"+
			"i2cp.closeIdleTime=%s",
			f.CloseIdle,
			f.CloseIdleTime)
	}

	// Log when close idle is not enabled
	log.Debug("Close idle settings not applied")
	return ""
}

// DoZero returns the zero hop and fast receive configuration string settings
func (f *I2PConfig) DoZero() string {
	// Build settings using slices for cleaner concatenation
	var settings []string

	// Add inbound zero hop setting if enabled
	if f.InAllowZeroHop == "true" {
		settings = append(settings, fmt.Sprintf("inbound.allowZeroHop=%s", f.InAllowZeroHop))
	}

	// Add outbound zero hop setting if enabled
	if f.OutAllowZeroHop == "true" {
		settings = append(settings, fmt.Sprintf("outbound.allowZeroHop=%s", f.OutAllowZeroHop))
	}

	// Add fast receive setting if enabled
	if f.FastRecieve == "true" {
		settings = append(settings, f.FastRecieve)
	}

	// Join all settings with spaces
	result := strings.Join(settings, " ")

	// Log the final settings
	log.WithField("zeroHopSettings", result).Debug("Zero hop settings applied")

	return result
}

// Print returns a slice of strings containing all the I2P configuration settings
func (f *I2PConfig) Print() []string {
	// Get lease set settings
	lsk, lspk, lspsk := f.Leasesetsettings()

	// Build the configuration settings slice
	settings := []string{
		fmt.Sprintf("inbound.length=%s", f.InLength),
		fmt.Sprintf("outbound.length=%s", f.OutLength),
		fmt.Sprintf("inbound.lengthVariance=%s", f.InVariance),
		fmt.Sprintf("outbound.lengthVariance=%s", f.OutVariance),
		fmt.Sprintf("inbound.backupQuantity=%s", f.InBackupQuantity),
		fmt.Sprintf("outbound.backupQuantity=%s", f.OutBackupQuantity),
		fmt.Sprintf("inbound.quantity=%s", f.InQuantity),
		fmt.Sprintf("outbound.quantity=%s", f.OutQuantity),
		f.DoZero(), // Zero hop settings
		fmt.Sprintf("i2cp.gzip=%s", f.UseCompression),
		f.Reduce(),       // Reduce idle settings
		f.Close(),        // Close idle settings
		f.Reliability(),  // Message reliability
		f.EncryptLease(), // Lease encryption
		lsk, lspk, lspsk, // Lease set keys
		f.Accesslisttype(),         // Access list type
		f.Accesslist(),             // Access list
		f.LeaseSetEncryptionType(), // Lease set encryption type
	}

	return settings
}

// Accesslisttype returns the I2CP access list configuration string based on the AccessListType setting
func (f *I2PConfig) Accesslisttype() string {
	switch f.AccessListType {
	case "whitelist":
		log.Debug("Access list type set to whitelist")
		return fmt.Sprintf("i2cp.enableAccessList=true")
	case "blacklist":
		log.Debug("Access list type set to blacklist")
		return fmt.Sprintf("i2cp.enableBlackList=true")
	case "none":
		log.Debug("Access list type set to none")
		return ""
	default:
		log.Debug("Access list type not set")
		return ""
	}
}

// Accesslist generates the I2CP access list configuration string based on the configured access list
func (f *I2PConfig) Accesslist() string {
	// Only proceed if access list type and values are set
	if f.AccessListType != "" && len(f.AccessList) > 0 {
		// Join access list entries with commas
		accessList := strings.Join(f.AccessList, ",")

		// Log the generated access list
		log.WithField("accessList", accessList).Debug("Access list generated")

		// Return formatted access list configuration
		return fmt.Sprintf("i2cp.accessList=%s", accessList)
	}

	// Log when access list is not set
	log.Debug("Access list not set")
	return ""
}

// LeaseSetEncryptionType returns the I2CP lease set encryption type configuration string.
// If no encryption type is set, returns default value "4,0".
// Validates that all encryption types are valid integers.
func (f *I2PConfig) LeaseSetEncryptionType() string {
	// Use default encryption type if none specified
	if f.LeaseSetEncryption == "" {
		log.Debug("Using default lease set encryption type: 4,0")
		return "i2cp.leaseSetEncType=4,0"
	}

	// Validate each encryption type is a valid integer
	for _, s := range strings.Split(f.LeaseSetEncryption, ",") {
		if _, err := strconv.Atoi(s); err != nil {
			log.WithField("invalidType", s).Panic("Invalid encrypted leaseSet type")
			//panic("Invalid encrypted leaseSet type: " + s)
		}
	}

	// Log and return the configured encryption type
	log.WithField("leaseSetEncType", f.LeaseSetEncryption).Debug("Lease set encryption type set")
	return fmt.Sprintf("i2cp.leaseSetEncType=%s", f.LeaseSetEncryption)
}

func NewConfig(opts ...func(*I2PConfig) error) (*I2PConfig, error) {
	var config I2PConfig
	config.SamHost = "127.0.0.1"
	config.SamPort = "7656"
	config.SamMin = "3.0"
	config.SamMax = "3.2"
	config.TunName = ""
	config.TunType = "server"
	config.Style = "STREAM"
	config.InLength = "3"
	config.OutLength = "3"
	config.InQuantity = "2"
	config.OutQuantity = "2"
	config.InVariance = "1"
	config.OutVariance = "1"
	config.InBackupQuantity = "3"
	config.OutBackupQuantity = "3"
	config.InAllowZeroHop = "false"
	config.OutAllowZeroHop = "false"
	config.EncryptLeaseSet = "false"
	config.LeaseSetKey = ""
	config.LeaseSetPrivateKey = ""
	config.LeaseSetPrivateSigningKey = ""
	config.FastRecieve = "false"
	config.UseCompression = "true"
	config.ReduceIdle = "false"
	config.ReduceIdleTime = "15"
	config.ReduceIdleQuantity = "4"
	config.CloseIdle = "false"
	config.CloseIdleTime = "300000"
	config.MessageReliability = "none"
	for _, o := range opts {
		if err := o(&config); err != nil {
			return nil, err
		}
	}
	return &config, nil
}

// options map
type Options map[string]string

// obtain sam options as list of strings
func (opts Options) AsList() (ls []string) {
	for k, v := range opts {
		ls = append(ls, fmt.Sprintf("%s=%s", k, v))
	}
	return
}

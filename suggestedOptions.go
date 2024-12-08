package sam3

import (
	"net"
	"net/http"
	"os"
	"strings"

	logger "github.com/go-i2p/sam3/log"
	sam3opts "github.com/go-i2p/sam3/opts"
	"github.com/sirupsen/logrus"
)

func PrimarySessionString() string {
	log.Debug("Determining primary session type")
	_, err := http.Get("http://127.0.0.1:7070")
	if err != nil {
		log.WithError(err).Debug("Failed to connect to 127.0.0.1:7070, trying 127.0.0.1:7657")
		_, err := http.Get("http://127.0.0.1:7657")
		if err != nil {
			return "MASTER"
		}
		log.Debug("Connected to 127.0.0.1:7657, attempting to create a PRIMARY session")
		// at this point we're probably running on Java I2P and thus probably
		// have a PRIMARY session. Just to be sure, try to make one, check
		// for errors, then immediately close it.
		testSam, err := NewSAM(SAMDefaultAddr(""))
		if err != nil {
			log.WithError(err).Debug("Failed to create SAM instance, assuming MASTER session")
			return "MASTER"
		}
		newKeys, err := testSam.NewKeys()
		if err != nil {
			log.WithError(err).Debug("Failed to create new keys, assuming MASTER session")
			return "MASTER"
		}
		primarySession, err := testSam.newPrimarySession("PRIMARY", "primaryTestTunnel", newKeys, sam3opts.Options_Small)
		if err != nil {
			log.WithError(err).Debug("Failed to create primary session, assuming MASTER session")
			return "MASTER"
		}
		primarySession.Close()
		log.Debug("Successfully created and closed a PRIMARY session")
		return "PRIMARY"
	}
	log.Debug("Connected to 127.0.0.1:7070, assuming MASTER session")
	return "MASTER"
}

var PrimarySessionSwitch string = PrimarySessionString()

func getEnv(key, fallback string) string {
	logger.InitializeSAM3Logger()
	value, ok := os.LookupEnv(key)
	if !ok {
		log.WithFields(logrus.Fields{
			"key":      key,
			"fallback": fallback,
		}).Debug("Environment variable not set, using fallback")
		return fallback
	}
	log.WithFields(logrus.Fields{
		"key":   key,
		"value": value,
	}).Debug("Retrieved environment variable")
	return value
}

var (
	SAM_HOST = getEnv("sam_host", "127.0.0.1")
	SAM_PORT = getEnv("sam_port", "7656")
)

func SAMDefaultAddr(fallforward string) string {
	if fallforward == "" {
		addr := net.JoinHostPort(SAM_HOST, SAM_PORT)
		log.WithField("addr", addr).Debug("Using default SAM address")
		return addr
	}
	log.WithField("addr", fallforward).Debug("Using fallforward SAM address")
	return fallforward
}

func GenerateOptionString(opts []string) string {
	optStr := strings.Join(opts, " ")
	log.WithField("options", optStr).Debug("Generating option string")
	if strings.Contains(optStr, "i2cp.leaseSetEncType") {
		log.Debug("i2cp.leaseSetEncType already present in options")
		return optStr
	}
	finalOpts := optStr + " i2cp.leaseSetEncType=4,0"
	log.WithField("finalOptions", finalOpts).Debug("Added default i2cp.leaseSetEncType to options")
	return finalOpts
	// return optStr + " i2cp.leaseSetEncType=4,0"
}

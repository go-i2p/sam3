package config

import (
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Add transport options
type TransportOptions struct {
	UseCompression     string
	FastReceive        string
	MessageReliability string
	CloseIdleTimeout   time.Duration
	CloseIdle          bool
	ReduceIdleTimeout  time.Duration
	ReduceIdle         bool
	ReduceIdleQuantity int
}

func (f *TransportOptions) ReduceOnIdle() string {
	return boolToStr(f.ReduceIdle)
}

func (f *TransportOptions) ReduceQuantity() string {
	return strconv.Itoa(f.ReduceIdleQuantity)
}

func (f *TransportOptions) CloseOnIdle() string {
	return boolToStr(f.CloseIdle)
}

func (f *TransportOptions) DoFastReceive() string {
	if f.FastReceive == "true" {
		return " " + f.FastReceive + " "
	}
	return ""
}

// Reliability returns the message reliability setting in the form of "i2cp.messageReliability=reliability"
func (f *TransportOptions) Reliability() string {
	if f.MessageReliability != "" {
		log.WithField("reliability", f.MessageReliability).Debug("Message reliability set")
		return " i2cp.messageReliability=" + f.MessageReliability + " "
	}
	log.Debug("Message reliability not set")
	return ""
}

// Reduce returns the reduce idle settings in the form of "i2cp.reduceOnIdle=true i2cp.reduceIdleTime=time i2cp.reduceQuantity=quantity"
func (f *TransportOptions) Reduce() string {
	if f.ReduceIdle {
		log.WithFields(logrus.Fields{
			"reduceIdle":         f.ReduceIdle,
			"reduceIdleTime":     f.ReduceIdleTimeout.String(),
			"reduceIdleQuantity": f.ReduceIdleQuantity,
		}).Debug("Reduce idle settings applied")
		return "i2cp.reduceOnIdle=" + f.ReduceOnIdle() + "i2cp.reduceIdleTime=" + f.ReduceIdleTimeout.String() + "i2cp.reduceQuantity=" + f.ReduceQuantity()
	}
	log.Debug("Reduce idle settings not applied")
	return ""
}

// Close returns the close idle settings in the form of "i2cp.closeOnIdle=true i2cp.closeIdleTime=time"
func (f *TransportOptions) Close() string {
	if f.CloseIdle {
		log.WithFields(logrus.Fields{
			"closeIdle":     f.CloseIdle,
			"closeIdleTime": f.CloseIdleTimeout.String(),
		}).Debug("Close idle settings applied")
		return "i2cp.closeOnIdle=" + f.CloseOnIdle() + "i2cp.closeIdleTime=" + f.CloseIdleTimeout.String()
	}
	log.Debug("Close idle settings not applied")
	return ""
}

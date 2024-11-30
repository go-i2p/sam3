package config

import (
	"strconv"
	"time"
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
	Reliability        string
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
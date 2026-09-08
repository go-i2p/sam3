package config

import (
	"fmt"
	"strconv"
)

type TunnelOptions struct {
	InAllowZeroHop    bool
	OutAllowZeroHop   bool
	InLength          int
	OutLength         int
	InQuantity        int
	OutQuantity       int
	InVariance        int
	OutVariance       int
	InBackupQuantity  int
	OutBackupQuantity int
}

func (f *TunnelOptions) InboundDoZero() string {
	val := boolToStr(f.InAllowZeroHop)
	return fmt.Sprintf(" inbound.allowZeroHop=%s ", val)
}

func (f *TunnelOptions) OutboundDoZero() string {
	val := boolToStr(f.OutAllowZeroHop)
	return fmt.Sprintf(" outbound.allowZeroHop=%s ", val)
}

func (f *TunnelOptions) InboundLength() string {
	val := strconv.Itoa(f.InLength)
	return fmt.Sprintf(" inbound.length=%s ", val)
}

func (f *TunnelOptions) OutboundLength() string {
	val := strconv.Itoa(f.OutLength)
	return fmt.Sprintf(" outbound.length=%s ", val)
}

func (f *TunnelOptions) InboundQuantity() string {
	val := strconv.Itoa(f.InQuantity)
	return fmt.Sprintf(" inbound.quantity=%s ", val)
}

func (f *TunnelOptions) OutboundQuantity() string {
	val := strconv.Itoa(f.OutQuantity)
	return fmt.Sprintf(" outbound.quantity=%s ", val)
}

func (f *TunnelOptions) InboundVariance() string {
	val := strconv.Itoa(f.InVariance)
	return fmt.Sprintf(" inbound.variance=%s ", val)
}

func (f *TunnelOptions) OutboundVariance() string {
	val := strconv.Itoa(f.OutVariance)
	return fmt.Sprintf(" outbound.variance=%s ", val)
}

func (f *TunnelOptions) InboundBackupQuantity() string {
	val := strconv.Itoa(f.InBackupQuantity)
	return fmt.Sprintf(" inbound.backupQuantity=%s ", val)
}

func (f *TunnelOptions) OutboundBackupQuantity() string {
	val := strconv.Itoa(f.OutBackupQuantity)
	return fmt.Sprintf(" outbound.backupQuantity=%s ", val)
}

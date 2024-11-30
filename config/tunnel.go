package config

import "strconv"

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
	return boolToStr(f.InAllowZeroHop)
}

func (f *TunnelOptions) OutboundDoZero() string {
	return boolToStr(f.OutAllowZeroHop)
}

func (f *TunnelOptions) InboundLength() string {
	return strconv.Itoa(f.InLength)
}

func (f *TunnelOptions) OutboundLength() string {
	return strconv.Itoa(f.OutLength)
}

func (f *TunnelOptions) InboundQuantity() string {
	return strconv.Itoa(f.InQuantity)
}

func (f *TunnelOptions) OutboundQuantity() string {
	return strconv.Itoa(f.OutQuantity)
}

func (f *TunnelOptions) InboundVariance() string {
	return strconv.Itoa(f.InVariance)
}

func (f *TunnelOptions) OutboundVariance() string {
	return strconv.Itoa(f.OutVariance)
}

func (f *TunnelOptions) InboundBackupQuantity() string {
	return strconv.Itoa(f.InBackupQuantity)
}

func (f *TunnelOptions) OutboundBackupQuantity() string {
	return strconv.Itoa(f.OutBackupQuantity)
}

// DoZero returns the zero hop settings in the form of "inbound.allowZeroHop=true outbound.allowZeroHop=true fastRecieve=true"
func (f *TunnelOptions) DoZero() string {
	r := ""
	if f.InAllowZeroHop {
		r += " inbound.allowZeroHop=" + f.InboundDoZero() + " "
	}
	if f.OutAllowZeroHop {
		r += " outbound.allowZeroHop= " + f.OutboundDoZero() + " "
	}
	log.WithField("zeroHopSettings", r).Debug("Zero hop settings applied")
	return r
}

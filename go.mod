module github.com/go-i2p/sam3

go 1.26.3

require (
	github.com/go-i2p/i2pkeys v0.33.92
	github.com/go-i2p/logger v0.1.60000-0.20260701134448-2648c3b0e040
	github.com/sirupsen/logrus v1.10.2
)

require golang.org/x/sys v0.48.0 // indirect

replace github.com/go-i2p/i2pkeys v0.33.92 => ../i2pkeys

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)

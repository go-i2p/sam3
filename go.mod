module github.com/go-i2p/sam3

go 1.23.3

require (
	github.com/go-i2p/i2pkeys v0.33.92
	github.com/go-i2p/logger v0.0.0-20241123010126-3050657e5d0c
	github.com/sirupsen/logrus v1.9.3
)

require golang.org/x/sys v0.27.0 // indirect

replace github.com/go-i2p/i2pkeys v0.33.92 => ../i2pkeys

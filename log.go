package sam3

import (
	logger "github.com/go-i2p/logger"
)

var (
	log  *logger.Logger
)

func InitializeSAM3Logger() {
	logger.InitializeGoI2PLogger()
	log = GetSAM3Logger()
}

// GetSAM3Logger returns the initialized logger
func GetSAM3Logger() *logger.Logger {
	return logger.GetGoI2PLogger()
}

func init() {
	InitializeSAM3Logger()	
}

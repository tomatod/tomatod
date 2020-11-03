package tcpip

import (
	"log"
)

var logLevel int

const (
	LOG_ERROR int = 1
	LOG_INFO int = 2
	LOG_DEBUG int = 3
)

func init() {
	logLevel = LOG_ERROR
}

func SetLogLevel(level int) {
	logLevel = level
}

func loging(level int, msg ...interface{}) {
	if logLevel != level {
		return
	}
	log.Println(msg...)
}

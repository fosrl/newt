//go:build darwin
// +build darwin

package main

/*
#cgo CFLAGS: -I../PacketTunnel
#include "../PacketTunnel/OSLogBridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// OSLogWriter is a LogWriter implementation that writes to Apple's os_log
type OSLogWriter struct {
	subsystem string
	category  string
	prefix    string
}

// NewOSLogWriter creates a new OSLogWriter
func NewOSLogWriter(subsystem, category, prefix string) *OSLogWriter {
	writer := &OSLogWriter{
		subsystem: subsystem,
		category:  category,
		prefix:    prefix,
	}

	// Initialize the OS log bridge
	cSubsystem := C.CString(subsystem)
	cCategory := C.CString(category)
	defer C.free(unsafe.Pointer(cSubsystem))
	defer C.free(unsafe.Pointer(cCategory))

	C.initOSLogBridge(cSubsystem, cCategory)

	return writer
}

// Write implements the LogWriter interface
func (w *OSLogWriter) Write(level LogLevel, timestamp time.Time, message string) {
	// Get caller information (skip 3 frames to get to the actual caller)
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		file = "unknown"
		line = 0
	} else {
		// Get just the filename, not the full path
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}
	}

	formattedTime := timestamp.Format("2006-01-02 15:04:05.000")
	fullMessage := fmt.Sprintf("[%s] [%s] [%s] %s:%d - %s",
		formattedTime, level.String(), w.prefix, file, line, message)

	cMessage := C.CString(fullMessage)
	defer C.free(unsafe.Pointer(cMessage))

	// Map Go log levels to os_log levels:
	// 0=DEBUG, 1=INFO, 2=DEFAULT (WARN), 3=ERROR
	var osLogLevel C.int
	switch level {
	case DEBUG:
		osLogLevel = 0 // DEBUG
	case INFO:
		osLogLevel = 1 // INFO
	case WARN:
		osLogLevel = 2 // DEFAULT
	case ERROR, FATAL:
		osLogLevel = 3 // ERROR
	default:
		osLogLevel = 2 // DEFAULT
	}

	C.logToOSLog(osLogLevel, cMessage)
}

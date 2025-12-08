package logger

import (
	"fmt"
	"os"
	"time"
)

// LogWriter is an interface for writing log messages
// Implement this interface to create custom log backends (OS log, syslog, etc.)
type LogWriter interface {
	// Write writes a log message with the given level, timestamp, and formatted message
	Write(level LogLevel, timestamp time.Time, message string)
}

// StandardWriter is the default log writer that writes to an io.Writer
type StandardWriter struct {
	output   *os.File
	timezone *time.Location
}

// NewStandardWriter creates a new standard writer with the default configuration
func NewStandardWriter() *StandardWriter {
	// Get timezone from environment variable or use local timezone
	timezone := os.Getenv("LOGGER_TIMEZONE")
	var location *time.Location
	var err error

	if timezone != "" {
		location, err = time.LoadLocation(timezone)
		if err != nil {
			// If invalid timezone, fall back to local
			location = time.Local
		}
	} else {
		location = time.Local
	}

	return &StandardWriter{
		output:   os.Stdout,
		timezone: location,
	}
}

// SetOutput sets the output destination
func (w *StandardWriter) SetOutput(output *os.File) {
	w.output = output
}

// Write implements the LogWriter interface
func (w *StandardWriter) Write(level LogLevel, timestamp time.Time, message string) {
	formattedTime := timestamp.In(w.timezone).Format("2006/01/02 15:04:05")
	fmt.Fprintf(w.output, "%s: %s %s\n", level.String(), formattedTime, message)
}

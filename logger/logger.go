package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Logger struct holds the logger instance
type Logger struct {
	logger *log.Logger
	level  LogLevel
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", 0),
		level:  DEBUG,
	}
}

// Init initializes the default logger
func Init() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger()
	})
	return defaultLogger
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	if defaultLogger == nil {
		Init()
	}
	return defaultLogger
}

// SetLevel sets the minimum logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// SetOutput sets the output destination for the logger
func (l *Logger) SetOutput(w io.Writer) {
	l.logger.SetOutput(w)
}

// log handles the actual logging
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

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

	timestamp := time.Now().In(location).Format("2006/01/02 15:04:05")
	message := fmt.Sprintf(format, args...)
	l.logger.Printf("%s: %s %s", level.String(), timestamp, message)
}

// Debug logs debug level messages
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs info level messages
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs warning level messages
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs error level messages
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs fatal level messages and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

// Global helper functions
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}

// SetOutput sets the output destination for the default logger
func SetOutput(w io.Writer) {
	GetLogger().SetOutput(w)
}

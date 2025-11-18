package logger

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger struct holds the logger instance
type Logger struct {
	writer LogWriter
	level  LogLevel
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// NewLogger creates a new logger instance with the default StandardWriter
func NewLogger() *Logger {
	return &Logger{
		writer: NewStandardWriter(),
		level:  DEBUG,
	}
}

// NewLoggerWithWriter creates a new logger instance with a custom LogWriter
func NewLoggerWithWriter(writer LogWriter) *Logger {
	return &Logger{
		writer: writer,
		level:  DEBUG,
	}
}

// Init initializes the default logger
func Init(logger *Logger) *Logger {
	once.Do(func() {
		if logger != nil {
			defaultLogger = logger
			return
		}
		defaultLogger = NewLogger()
	})
	return defaultLogger
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	if defaultLogger == nil {
		Init(nil)
	}
	return defaultLogger
}

// SetLevel sets the minimum logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// SetOutput sets the output destination for the logger (only works with StandardWriter)
func (l *Logger) SetOutput(output *os.File) {
	if sw, ok := l.writer.(*StandardWriter); ok {
		sw.SetOutput(output)
	}
}

// log handles the actual logging
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	message := fmt.Sprintf(format, args...)
	l.writer.Write(level, time.Now(), message)
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
func SetOutput(output *os.File) {
	GetLogger().SetOutput(output)
}

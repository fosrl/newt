# Extensible Logger

This logger package provides a flexible logging system that can be extended with custom log writers.

## Basic Usage (Current Behavior)

The logger works exactly as before with no changes required:

```go
package main

import "your-project/logger"

func main() {
    // Use default logger
    logger.Info("This works as before")
    logger.Debug("Debug message")
    logger.Error("Error message")
    
    // Or create a custom instance
    log := logger.NewLogger()
    log.SetLevel(logger.INFO)
    log.Info("Custom logger instance")
}
```

## Custom Log Writers

To use a custom log backend, implement the `LogWriter` interface:

```go
type LogWriter interface {
    Write(level LogLevel, timestamp time.Time, message string)
}
```

### Example: OS Log Writer (macOS/iOS)

```go
package main

import "your-project/logger"

func main() {
    // Create an OS log writer
    osWriter := logger.NewOSLogWriter(
        "net.pangolin.Pangolin.PacketTunnel",
        "PangolinGo",
        "MyApp",
    )
    
    // Create a logger with the OS log writer
    log := logger.NewLoggerWithWriter(osWriter)
    log.SetLevel(logger.DEBUG)
    
    // Use it just like the standard logger
    log.Info("This message goes to os_log")
    log.Error("Error logged to os_log")
}
```

### Example: Custom Writer

```go
package main

import (
    "fmt"
    "time"
    "your-project/logger"
)

// CustomWriter writes logs to a custom destination
type CustomWriter struct {
    // your custom fields
}

func (w *CustomWriter) Write(level logger.LogLevel, timestamp time.Time, message string) {
    // Your custom logging logic
    fmt.Printf("[CUSTOM] %s [%s] %s\n", timestamp.Format(time.RFC3339), level.String(), message)
}

func main() {
    customWriter := &CustomWriter{}
    log := logger.NewLoggerWithWriter(customWriter)
    log.Info("Custom logging!")
}
```

### Example: Multi-Writer (Log to Multiple Destinations)

```go
package main

import (
    "time"
    "your-project/logger"
)

// MultiWriter writes to multiple log writers
type MultiWriter struct {
    writers []logger.LogWriter
}

func NewMultiWriter(writers ...logger.LogWriter) *MultiWriter {
    return &MultiWriter{writers: writers}
}

func (w *MultiWriter) Write(level logger.LogLevel, timestamp time.Time, message string) {
    for _, writer := range w.writers {
        writer.Write(level, timestamp, message)
    }
}

func main() {
    // Log to both standard output and OS log
    standardWriter := logger.NewStandardWriter()
    osWriter := logger.NewOSLogWriter("com.example.app", "Main", "App")
    
    multiWriter := NewMultiWriter(standardWriter, osWriter)
    log := logger.NewLoggerWithWriter(multiWriter)
    
    log.Info("This goes to both stdout and os_log!")
}
```

## API Reference

### Creating Loggers

- `NewLogger()` - Creates a logger with the default StandardWriter
- `NewLoggerWithWriter(writer LogWriter)` - Creates a logger with a custom writer

### Built-in Writers

- `NewStandardWriter()` - Standard writer that outputs to stdout (default)
- `NewOSLogWriter(subsystem, category, prefix string)` - OS log writer for macOS/iOS (example)

### Logger Methods

- `SetLevel(level LogLevel)` - Set minimum log level
- `SetOutput(output *os.File)` - Set output file (StandardWriter only)
- `Debug(format string, args ...interface{})` - Log debug message
- `Info(format string, args ...interface{})` - Log info message
- `Warn(format string, args ...interface{})` - Log warning message
- `Error(format string, args ...interface{})` - Log error message
- `Fatal(format string, args ...interface{})` - Log fatal message and exit

### Global Functions

For convenience, you can use global functions that use the default logger:

- `logger.Debug(format, args...)`
- `logger.Info(format, args...)`
- `logger.Warn(format, args...)`
- `logger.Error(format, args...)`
- `logger.Fatal(format, args...)`
- `logger.SetOutput(output *os.File)`

## Migration Guide

No changes needed! The logger maintains 100% backward compatibility. Your existing code will continue to work without modifications.

If you want to switch to a custom writer:
1. Create your writer implementing `LogWriter`
2. Use `NewLoggerWithWriter()` instead of `NewLogger()`
3. That's it!

// Example usage patterns for the extensible logger
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fosrl/newt/logger"
)

// Example 1: Using the default logger (works exactly as before)
func exampleDefaultLogger() {
	logger.Info("Starting application")
	logger.Debug("Debug information")
	logger.Warn("Warning message")
	logger.Error("Error occurred")
}

// Example 2: Using a custom logger instance with standard writer
func exampleCustomInstance() {
	log := logger.NewLogger()
	log.SetLevel(logger.INFO)
	log.Info("This is from a custom instance")
}

// Example 3: Custom writer that adds JSON formatting
type JSONWriter struct{}

func (w *JSONWriter) Write(level logger.LogLevel, timestamp time.Time, message string) {
	fmt.Printf("{\"time\":\"%s\",\"level\":\"%s\",\"message\":\"%s\"}\n",
		timestamp.Format(time.RFC3339),
		level.String(),
		message)
}

func exampleJSONLogger() {
	jsonWriter := &JSONWriter{}
	log := logger.NewLoggerWithWriter(jsonWriter)
	log.Info("This will be logged as JSON")
}

// Example 4: File writer
type FileWriter struct {
	file *os.File
}

func NewFileWriter(filename string) (*FileWriter, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileWriter{file: file}, nil
}

func (w *FileWriter) Write(level logger.LogLevel, timestamp time.Time, message string) {
	fmt.Fprintf(w.file, "[%s] %s: %s\n",
		timestamp.Format("2006-01-02 15:04:05"),
		level.String(),
		message)
}

func (w *FileWriter) Close() error {
	return w.file.Close()
}

func exampleFileLogger() {
	fileWriter, err := NewFileWriter("/tmp/app.log")
	if err != nil {
		panic(err)
	}
	defer fileWriter.Close()

	log := logger.NewLoggerWithWriter(fileWriter)
	log.Info("This goes to a file")
}

// Example 5: Multi-writer to log to multiple destinations
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

func exampleMultiWriter() {
	// Log to both stdout and a file
	standardWriter := logger.NewStandardWriter()
	fileWriter, _ := NewFileWriter("/tmp/app.log")

	multiWriter := NewMultiWriter(standardWriter, fileWriter)
	log := logger.NewLoggerWithWriter(multiWriter)

	log.Info("This goes to both stdout and file!")
}

// Example 6: Conditional writer (only log errors to a specific destination)
type ErrorOnlyWriter struct {
	writer logger.LogWriter
}

func NewErrorOnlyWriter(writer logger.LogWriter) *ErrorOnlyWriter {
	return &ErrorOnlyWriter{writer: writer}
}

func (w *ErrorOnlyWriter) Write(level logger.LogLevel, timestamp time.Time, message string) {
	if level >= logger.ERROR {
		w.writer.Write(level, timestamp, message)
	}
}

func exampleConditionalWriter() {
	errorWriter, _ := NewFileWriter("/tmp/errors.log")
	errorOnlyWriter := NewErrorOnlyWriter(errorWriter)

	log := logger.NewLoggerWithWriter(errorOnlyWriter)
	log.Info("This won't be logged")
	log.Error("This will be logged to errors.log")
}

/* Example 7: OS Log Writer (macOS/iOS only)
// Uncomment on Darwin platforms

func exampleOSLogWriter() {
	osWriter := logger.NewOSLogWriter(
		"net.pangolin.Pangolin.PacketTunnel",
		"PangolinGo",
		"MyApp",
	)

	log := logger.NewLoggerWithWriter(osWriter)
	log.Info("This goes to os_log and can be viewed with Console.app")
}
*/

func main() {
	fmt.Println("=== Example 1: Default Logger ===")
	exampleDefaultLogger()

	fmt.Println("\n=== Example 2: Custom Instance ===")
	exampleCustomInstance()

	fmt.Println("\n=== Example 3: JSON Logger ===")
	exampleJSONLogger()

	fmt.Println("\n=== Example 4: File Logger ===")
	exampleFileLogger()

	fmt.Println("\n=== Example 5: Multi-Writer ===")
	exampleMultiWriter()

	fmt.Println("\n=== Example 6: Conditional Writer ===")
	exampleConditionalWriter()
}

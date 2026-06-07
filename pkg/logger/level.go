package logger

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelStrings = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

// String returns the string representation of the log level
func (l LogLevel) String() string {
	if s, ok := levelStrings[l]; ok {
		return s
	}
	return "UNKNOWN"
}

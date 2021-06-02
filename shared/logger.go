package shared

// Logger is an interface which if satisfied will add debug logging to this library
type Logger interface {
	Printf(format string, v ...interface{})
}

// NOPLogger doesn't log - it is the default set on structs in this library
type NOPLogger struct{}

func (l *NOPLogger) Printf(format string, v ...interface{}) {
	return
}

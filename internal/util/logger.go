package util

// Logger 定义日志接口
type Logger interface {
	Info(...any)
	Infof(string, ...any)
	Warn(...any)
	Warnf(string, ...any)
	Error(...any)
	Errorf(string, ...any)
}

var _ Logger = (*SafeLogger)(nil)

// SafeLogger 包装日志实例，防止空指针错误
type SafeLogger struct {
	logger Logger
}

// NewSafeLogger 创建安全的日志包装器
func NewSafeLogger(logger Logger) *SafeLogger {
	return &SafeLogger{logger: logger}
}

// Info 记录信息日志
func (sl *SafeLogger) Info(v ...any) {
	if sl.logger != nil {
		sl.logger.Info(v...)
	}
}

// Infof 记录格式化信息日志
func (sl *SafeLogger) Infof(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Infof(format, v...)
	}
}

// Warn 记录警告日志
func (sl *SafeLogger) Warn(v ...any) {
	if sl.logger != nil {
		sl.logger.Warn(v...)
	}
}

// Warnf 记录格式化警告日志
func (sl *SafeLogger) Warnf(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Warnf(format, v...)
	}
}

// Error 记录错误日志
func (sl *SafeLogger) Error(v ...any) {
	if sl.logger != nil {
		sl.logger.Error(v...)
	}
}

// Errorf 记录格式化错误日志
func (sl *SafeLogger) Errorf(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Errorf(format, v...)
	}
}

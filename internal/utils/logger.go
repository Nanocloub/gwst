package utils

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

// nullLogger 实现一个空的日志记录器，用于当没有提供 logger 时
type nullLogger struct{}

func (n *nullLogger) Info(...any)           {}
func (n *nullLogger) Infof(string, ...any)  {}
func (n *nullLogger) Warn(...any)           {}
func (n *nullLogger) Warnf(string, ...any)  {}
func (n *nullLogger) Error(...any)          {}
func (n *nullLogger) Errorf(string, ...any) {}

// sharedNullLogger 是全局单例，避免每次 NewSafeLoggerOrNull(nil) 都分配新对象
var sharedNullLogger Logger = &nullLogger{}

// NewSafeLoggerOrNull 创建一个安全的 logger，如果传入 nil 则返回 nullLogger
// 这是一个便捷函数，避免在各处重复 nil 检查逻辑
func NewSafeLoggerOrNull(logger Logger) Logger {
	if logger != nil {
		return logger
	}
	return sharedNullLogger
}

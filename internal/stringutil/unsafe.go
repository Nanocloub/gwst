package stringutil

import "unsafe"

// BytesToString 零拷贝将字节数组转换为字符串
//
// ⚠️ 重要警告：这是一个不安全的操作，违反了 Go 字符串的不可变性保证！
// - 对字节数组的任何修改都会同步影响返回的字符串
// - 返回的字符串不应该被存储或传递给其他 goroutine
// - 仅在确定字节数组不会被修改的临时场景中使用
//
// 使用场景：仅用于临时的性能优化（如加密/解密），使用后立即丢弃
// 不安全原因：违反了 Go 的字符串不可变性契约
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// StringToBytes 零拷贝将字符串转换为字节数组
//
// ⚠️ 重要警告：这是一个不安全的操作！
// - 如果字符串是字面量或常量，修改返回的字节数组会导致 panic
// - 修改返回的字节数组可能导致程序崩溃或数据损坏
// - 返回的字节数组不应该被修改
//
// 使用场景：仅用于只读操作（如哈希计算、比较）
// 不安全原因：可能导致运行时 panic 和内存损坏
func StringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

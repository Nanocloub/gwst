package utils

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	// StreamKeepaliveInterval 心跳帧发送间隔
	StreamKeepaliveInterval = 30 * time.Second
	// StreamReadTimeout 读超时：若该时间内心跳写入持续失败（连接断开），读操作超时退出
	StreamReadTimeout = 90 * time.Second
	// StreamKeepaliveWriteTimeout 心跳帧写超时
	StreamKeepaliveWriteTimeout = 10 * time.Second
)

// streamKeepaliveFrame 零长度帧头 [0x00, 0x00]。
// CryptoConn.Read 的 stream 模式遇到 ln==0 会自动 continue，对上层透明。
var streamKeepaliveFrame = []byte{0, 0}

// StreamKeepaliveConn 为 TCP/QUIC 流式连接添加应用层心跳，
// 功能等同于 WebSocket 模式的 ping goroutine。
//
// 工作原理：
//   - 每 StreamKeepaliveInterval 发送一个零长度帧 [0x00, 0x00] 作为心跳
//   - 成功发送后刷新读超时（StreamReadTimeout）
//   - 若隧道断开，心跳写入失败 → 停止刷新 → 读操作超时退出 → 连接清理
//   - CryptoConn.Read() 自动跳过零长度帧，对数据传输透明
type StreamKeepaliveConn struct {
	net.Conn  // CryptoConn (data path)
	rawConn   net.Conn
	writeMu   *sync.Mutex
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewStreamKeepaliveConn 创建带心跳的流式加密连接。
// rawConn: 底层 TCP/QUIC 连接
// cm: 加密管理器（可为 nil）
func NewStreamKeepaliveConn(rawConn net.Conn, cm CryptoManager) *StreamKeepaliveConn {
	ctx, cancel := context.WithCancel(context.Background())

	var writeMu sync.Mutex

	s := &StreamKeepaliveConn{
		rawConn: rawConn,
		writeMu: &writeMu,
		cancel:  cancel,
	}

	// CryptoConn 的写入通过 LockedConn 与心跳 goroutine 共享 writeMu
	s.Conn = NewCryptoConn(&LockedConn{Conn: rawConn, Mu: &writeMu}, cm, true)

	// 设置初始读超时
	rawConn.SetReadDeadline(time.Now().Add(StreamReadTimeout))

	go s.keepalive(ctx)

	return s
}

func (s *StreamKeepaliveConn) keepalive(ctx context.Context) {
	ticker := time.NewTicker(StreamKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// TryLock: 若数据拷贝正在写入，跳过本次心跳，避免阻塞。
			if !s.writeMu.TryLock() {
				continue
			}
			s.rawConn.SetWriteDeadline(time.Now().Add(StreamKeepaliveWriteTimeout))
			_, err := s.rawConn.Write(streamKeepaliveFrame)
			s.rawConn.SetWriteDeadline(time.Time{})
			s.writeMu.Unlock()
			if err != nil {
				s.rawConn.Close()
				return
			}
			s.rawConn.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		case <-ctx.Done():
			return
		}
	}
}

// Close 关闭连接并停止心跳 goroutine。
func (s *StreamKeepaliveConn) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.Conn.Close()
	})
	return err
}

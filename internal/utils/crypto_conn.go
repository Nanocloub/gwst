package utils

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"golang.org/x/net/websocket"
)

// CryptoConn 自动处理加密/解密的 net.Conn 包装器
type CryptoConn struct {
	net.Conn
	cm       CryptoManager
	isStream bool   // TCP/QUIC 为 true，WebSocket 为 false
	readMu   sync.Mutex // 只保护 readBuf 的访问
	readBuf  []byte     // 缓存流模式下解密多出的数据
}

// 编译时检查：确保 CryptoConn 实现 DeadlineWriter 接口
// 这防止在运行时因类型断言失败导致 panic
var _ DeadlineWriter = (*CryptoConn)(nil)

func NewCryptoConn(conn net.Conn, cm CryptoManager, isStream bool) net.Conn {
	return &CryptoConn{Conn: conn, cm: cm, isStream: isStream}
}

// cryptoBufferPool is used for temporary encryption/decryption buffers to reduce GC pressure
var cryptoBufferPool = sync.Pool{
	New: func() any {
		// Using UDPBufferSize (64KB+) to handle any possible packet size
		b := make([]byte, UDPBufferSize)
		return &b
	},
}

func (c *CryptoConn) Read(b []byte) (int, error) {
	for {
		// 先检查缓冲区（需要锁保护）
		c.readMu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		bufPtr := cryptoBufferPool.Get().(*[]byte)
		var tmpBuf []byte
		if bufPtr != nil {
			tmpBuf = *bufPtr
		} else {
			tmpBuf = make([]byte, UDPBufferSize)
		}

		var db []byte
		var err error
		oversized := false // 标记是否分配了超大 buffer（用于池管理）

		if !c.isStream {
			// WebSocket mode: Each message is a complete packet
			if ws, ok := c.Conn.(*websocket.Conn); ok {
				var message []byte
				err = websocket.Message.Receive(ws, &message)
				if err != nil {
					cryptoBufferPool.Put(bufPtr)
					return 0, err
				}
				if c.cm != nil {
					// WebSocket 消息是独立分配的，直接解密到 tmpBuf 安全
					db, err = c.cm.DecryptTo(tmpBuf, message)
					if err != nil {
						cryptoBufferPool.Put(bufPtr)
						return 0, err
					}
				} else {
					db = message
				}
			} else {
				n, err := c.Conn.Read(tmpBuf)
				if n == 0 && err != nil {
					cryptoBufferPool.Put(bufPtr)
					return 0, err
				}
				if c.cm != nil {
					// 使用 buffer 的后半部分作为解密目标，避免数据重叠
					dstOffset := len(tmpBuf) / 2
				db, err = c.cm.DecryptTo(tmpBuf[dstOffset:], tmpBuf[:n])
					if err != nil {
						cryptoBufferPool.Put(bufPtr)
						return 0, err
					}
				} else {
					db = tmpBuf[:n]
				}
			}
		} else {
			// Stream mode (TCP/QUIC): Read based on [Len(2)][Payload] protocol
			var lb [2]byte
			if _, err = io.ReadFull(c.Conn, lb[:]); err != nil {
				cryptoBufferPool.Put(bufPtr)
				return 0, err
			}
			ln := int(binary.BigEndian.Uint16(lb[:]))
			if ln == 0 {
				cryptoBufferPool.Put(bufPtr)
				continue // Zero-length frame, try next
			}

			// 检测异常超大包：防止池污染
			if ln > len(tmpBuf) {
				// 超大包：先回收标准 buffer，分配新的超大 buffer（一次性使用，不回池）
				// 需要双倍空间：前半部分存储加密数据，后半部分作为解密目标
				cryptoBufferPool.Put(bufPtr)
				tmpBuf = make([]byte, ln*2)
				bufPtr = nil
				oversized = true
			}

			if _, err = io.ReadFull(c.Conn, tmpBuf[:ln]); err != nil {
				if !oversized {
					cryptoBufferPool.Put(bufPtr)
				}
				return 0, err
			}

			if c.cm != nil {
				if ln < 32 { // Minimum size for AEGIS (Nonce + Tag)
					if !oversized {
						cryptoBufferPool.Put(bufPtr)
					}
					return 0, io.ErrUnexpectedEOF
				}
				// 使用 buffer 的后半部分作为解密目标，避免数据重叠
				// 前 ln 字节：加密数据，后部分：解密结果
				dstOffset := len(tmpBuf) / 2
				db, err = c.cm.DecryptTo(tmpBuf[dstOffset:], tmpBuf[:ln])
				if err != nil {
					if !oversized {
						cryptoBufferPool.Put(bufPtr)
					}
					return 0, err
				}
			} else {
				db = tmpBuf[:ln]
			}
		}

		rn := copy(b, db)
		if rn < len(db) {
			// 需要缓存剩余数据时加锁
			c.readMu.Lock()
			// 尝试复用现有 readBuf 容量，减少分配
			remaining := len(db) - rn
			if cap(c.readBuf) >= remaining {
				c.readBuf = c.readBuf[:remaining]
			} else {
				c.readBuf = make([]byte, remaining)
			}
			copy(c.readBuf, db[rn:])
			c.readMu.Unlock()
		}

		// 超大 buffer 不回池，避免池污染
		if !oversized && bufPtr != nil {
			cryptoBufferPool.Put(bufPtr)
		}

		if rn > 0 {
			return rn, nil
		}
		// if rn == 0 and err == nil, we loop to read next packet
	}
}

func (c *CryptoConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	bufPtr := cryptoBufferPool.Get().(*[]byte)
	defer cryptoBufferPool.Put(bufPtr)
	tmpBuf := *bufPtr

	if !c.isStream {
		// WebSocket: Write encrypted payload directly
		// 性能关键：直接加密到 tmpBuf，一次写入
		var eb []byte
		var err error
		if c.cm != nil {
			eb, err = c.cm.EncryptTo(tmpBuf, b)
			if err != nil {
				return 0, err
			}
		} else {
			eb = b
		}
		_, err = c.Conn.Write(eb)
		return len(b), err
	}

	// Stream mode: Split large data into frames to avoid length overflow (max 65535)
	// 性能关键：分块加密，避免单帧过大
	totalWritten := 0
	for len(b) > 0 {
		// Calculate max plaintext size for a single frame
		// Frame structure: [Len(2)][Payload]
		// total length (header excluded) must fit in 16 bits
		maxFramePayload := 65535
		maxPlaintext := maxFramePayload
		if c.cm != nil {
			// AEGIS overhead (Nonce + Tag) is 32 bytes
			// Ciphertext = Plaintext + 32. Must be <= 65535.
			maxPlaintext = maxFramePayload - 32
		}

		chunkSize := len(b)
		if chunkSize > maxPlaintext {
			chunkSize = maxPlaintext
		}

		var eb []byte
		var err error
		if c.cm != nil {
			eb, err = c.cm.EncryptTo(tmpBuf[2:], b[:chunkSize])
			if err != nil {
				return totalWritten, err
			}
		} else {
			// For non-encrypted stream, we just copy data to tmpBuf after the header
			copy(tmpBuf[2:], b[:chunkSize])
			eb = tmpBuf[2 : 2+chunkSize]
		}

		totalLen := len(eb)
		binary.BigEndian.PutUint16(tmpBuf[:2], uint16(totalLen))
		n, err := c.Conn.Write(tmpBuf[:2+totalLen])
		if err != nil {
			return totalWritten, err
		}
		// 检查是否完全写入
		if n != 2+totalLen {
			return totalWritten, io.ErrShortWrite
		}

		totalWritten += chunkSize
		b = b[chunkSize:]
	}

	return totalWritten, nil
}

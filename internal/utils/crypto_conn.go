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
	cm         CryptoManager
	isStream   bool
	readMu     sync.Mutex
	readBuf    []byte // 溢出缓存：调用方 b 装不下整帧时暂存多余数据
	readBufOff int    // readBuf 的消费偏移，避免每次 O(n) memmove
}

// 编译时检查：确保 CryptoConn 实现 DeadlineWriter 接口
// 这防止在运行时因类型断言失败导致 panic
var _ DeadlineWriter = (*CryptoConn)(nil)

func NewCryptoConn(conn net.Conn, cm CryptoManager, isStream bool) net.Conn {
	return &CryptoConn{Conn: conn, cm: cm, isStream: isStream}
}

// wsConnFromConn unwraps conn wrappers (e.g. LockedConn) to find a *websocket.Conn.
// LockedConn is only needed for Write (mutex with ping goroutine); reads can use
// the underlying *websocket.Conn directly because websocket.Message.Receive is
// self-framing and does not need the write mutex.
func wsConnFromConn(c net.Conn) (*websocket.Conn, bool) {
	for {
		if ws, ok := c.(*websocket.Conn); ok {
			return ws, true
		}
		if lc, ok := c.(*LockedConn); ok {
			c = lc.Conn
			continue
		}
		return nil, false
	}
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
		// ── 先消费溢出缓存 ────────────────────────────────────────────
		// readBufOff 是消费偏移，避免在大溢出帧下反复 memmove（O(n)→O(1)）。
		c.readMu.Lock()
		if c.readBufOff < len(c.readBuf) {
			n := copy(b, c.readBuf[c.readBufOff:])
			if c.readBufOff += n; c.readBufOff >= len(c.readBuf) {
				// 全部消费完。超过 32KB 时直接释放底层数组，让 GC 回收；
				// 避免偶发大帧（如握手/bulk upload）长期占据每连接 65KB。
				// 小缓冲（≤32KB）保留 capacity 供下次复用，减少 GC 压力。
				if cap(c.readBuf) > 32*1024 {
					c.readBuf = nil
				} else {
					c.readBuf = c.readBuf[:0]
				}
				c.readBufOff = 0
			}
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		// ── 从连接读取并解密下一帧 ────────────────────────────────────
		var (
			db     []byte
			err    error
			bufPtr *[]byte // 非 nil 时需在使用完后归还 cryptoBufferPool
		)

		if !c.isStream {
			// ── WebSocket 模式 ──────────────────────────────────────────
			// websocket.Message.Receive 内部自分配 message，
			// 阻塞等待期间不持有任何 pool buffer。
			if ws, ok := wsConnFromConn(c.Conn); ok {
				var message []byte
				if err = websocket.Message.Receive(ws, &message); err != nil {
					return 0, err
				}
				if c.cm == nil {
					db = message
				} else if len(message) >= 32 && len(message)-32 <= len(b) {
					// 快速路径：明文恰好装入调用方的 b。
					// 直接解密到 b，零 pool 操作，零额外拷贝。
					if db, err = c.cm.DecryptTo(b, message); err != nil {
						return 0, err
					}
					if len(db) == 0 {
						continue // 空明文帧，继续
					}
					return len(db), nil
				} else {
					// 溢出路径：明文 > len(b) 或消息过短，用 pool buffer 承载
					bufPtr = cryptoBufferPool.Get().(*[]byte)
					if db, err = c.cm.DecryptTo(*bufPtr, message); err != nil {
						cryptoBufferPool.Put(bufPtr)
						return 0, err
					}
				}
			} else {
				// 非 WebSocket 降级路径：pool buffer 作为 Read 目标，必须先获取
				bufPtr = cryptoBufferPool.Get().(*[]byte)
				tmpBuf := *bufPtr
				n, rerr := c.Conn.Read(tmpBuf)
				if n == 0 && rerr != nil {
					cryptoBufferPool.Put(bufPtr)
					return 0, rerr
				}
				if c.cm != nil {
					// 密文在 tmpBuf[:n]，解密目标放在 tmpBuf[n:] 避免重叠
					if db, err = c.cm.DecryptTo(tmpBuf[n:], tmpBuf[:n]); err != nil {
						cryptoBufferPool.Put(bufPtr)
						return 0, err
					}
				} else {
					db = tmpBuf[:n]
				}
			}
		} else {
			// ── Stream 模式（TCP/QUIC）：[Len(2)][Payload] 帧协议 ──────
			//
			// 关键内存优化：先读 2 字节头，阻塞期间不持有 pool buffer。
			var lb [2]byte
			if _, err = io.ReadFull(c.Conn, lb[:]); err != nil {
				return 0, err
			}
			ln := int(binary.BigEndian.Uint16(lb[:]))
			if ln == 0 {
				continue // 空帧，跳过
			}

			// ln 来自 uint16，最大 65535 < UDPBufferSize(65599)，
			// 因此 pool buffer 始终足够，无需 oversized 分支。
			bufPtr = cryptoBufferPool.Get().(*[]byte)
			tmpBuf := *bufPtr

			if _, err = io.ReadFull(c.Conn, tmpBuf[:ln]); err != nil {
				cryptoBufferPool.Put(bufPtr)
				return 0, err
			}

			if c.cm != nil {
				if ln < 32 { // AEGIS 最小有效密文 = Nonce(16) + Tag(16)
					cryptoBufferPool.Put(bufPtr)
					return 0, io.ErrUnexpectedEOF
				}
				// 快速路径：明文（ln-32 字节）装入调用方的 b。
				// 解密目标直接指向 b，省去一次拷贝，且不需要 readBuf。
				if ln-32 <= len(b) {
					if db, err = c.cm.DecryptTo(b, tmpBuf[:ln]); err != nil {
						cryptoBufferPool.Put(bufPtr)
						return 0, err
					}
					cryptoBufferPool.Put(bufPtr)
					if len(db) == 0 {
						continue
					}
					return len(db), nil
				}
				// 溢出路径：明文（ln-32）> len(b)。
				// pool buffer 剩余空间（tmpBuf[ln:]）能否放下明文？
				// 条件：len(tmpBuf)-ln >= ln-32，即 len(tmpBuf)+32 >= 2*ln。
				var decDst []byte
				if 2*ln <= len(tmpBuf)+32 {
					decDst = tmpBuf[ln:] // 就地：密文在前，明文在后，无重叠
				} else {
					decDst = make([]byte, ln-32) // 超大帧（>~32KB）：堆分配
				}
				if db, err = c.cm.DecryptTo(decDst, tmpBuf[:ln]); err != nil {
					cryptoBufferPool.Put(bufPtr)
					return 0, err
				}
			} else {
				db = tmpBuf[:ln]
			}
		}

		// ── 将解密结果写入调用方 b，超出部分存入 readBuf ────────────
		rn := copy(b, db)
		if rn < len(db) {
			c.readMu.Lock()
			remaining := len(db) - rn
			if cap(c.readBuf) >= remaining {
				c.readBuf = c.readBuf[:remaining]
			} else {
				c.readBuf = make([]byte, remaining)
			}
			c.readBufOff = 0
			copy(c.readBuf, db[rn:])
			c.readMu.Unlock()
		}
		if bufPtr != nil {
			cryptoBufferPool.Put(bufPtr)
		}
		if rn > 0 {
			return rn, nil
		}
		// rn == 0 且无错误（例如空明文帧）：继续读取下一帧
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
			// Check that the destination buffer has room for the encryption overhead
			// (nonce 16 bytes + tag 16 bytes = 32 bytes). If not, fall back to
			// heap-allocated Encrypt to avoid "destination buffer too small".
			if len(b)+32 <= len(tmpBuf) {
				eb, err = c.cm.EncryptTo(tmpBuf, b)
			} else {
				eb, err = c.cm.Encrypt(b)
			}
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

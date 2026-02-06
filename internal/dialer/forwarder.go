package dialer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/zijiren233/gencontainer/rwmap"

	"github.com/zijiren233/gwst/internal/utils"
)

const (
	DefaultUDPPoolSize            = 512
	DefaultUDPCleanupInterval     = 15 * time.Second
	DefaultUDPIdleTimeout         = time.Minute
	DefaultUDPEarlyDataHeaderName = "Sec-WebSocket-Protocol"
	DefaultUDPMaxEarlyDataSize    = 4 * 1024
)

// 导出接口别名
type Logger = utils.Logger
type CryptoManager = utils.CryptoManager
type deadlineWriter = utils.DeadlineWriter

// WebSocketDialer is an interface for dialing WebSocket connections
type WebSocketDialer interface {
	DialTCP() (io.ReadWriteCloser, error)
	DialUDP() (io.ReadWriteCloser, error)
	DialUDPWithHeaders(headers http.Header) (io.ReadWriteCloser, error)
}

var sharedUDPConnInfoPool = sync.Pool{
	New: func() any {
		return &udpConnInfo{
			setUpDone: make(chan struct{}),
		}
	},
}

func getUDPConnInfo() *udpConnInfo {
	u := sharedUDPConnInfoPool.Get().(*udpConnInfo)
	// Reset state for reuse
	u.Conn = nil
	u.dialErr = nil
	u.remoteAddr = nil
	u.setUpDone = make(chan struct{})
	u.setUpDoneOnce = sync.Once{}
	u.closed.Store(false)
	u.forwarder = nil
	u.framingCached.Store(false)
	return u
}

func putUDPConnInfo(u *udpConnInfo) {
	// Clear references to help GC
	u.Conn = nil
	u.remoteAddr = nil
	u.forwarder = nil
	sharedUDPConnInfoPool.Put(u)
}

type udpConnInfo struct {
	net.Conn
	dialErr       error
	remoteAddr    net.Addr // Store remote address instead of dialer
	setUpDone     chan struct{}
	lastActive    atomic.Int64
	setUpDoneOnce sync.Once
	dialLock      sync.Mutex
	closed        atomic.Bool // Use atomic for thread-safe access
	forwarder     *Forwarder
	needsFraming  bool        // 缓存是否需要帧封装的判断结果
	framingCached atomic.Bool // 标记是否已缓存
}

func (u *udpConnInfo) Close() error {
	u.dialLock.Lock()
	defer u.dialLock.Unlock()

	if u.closed.Load() {
		return nil
	}

	u.closed.Store(true)
	u.setUpDoneOnce.Do(func() {
		close(u.setUpDone)
	})

	if u.Conn != nil {
		return u.Conn.Close()
	}

	return nil
}

func (u *udpConnInfo) Setup() (net.Conn, error) {
	u.dialLock.Lock()
	defer u.dialLock.Unlock()
	defer u.setUpDoneOnce.Do(func() {
		close(u.setUpDone)
	})

	if u.closed.Load() {
		return nil, net.ErrClosed
	}

	if u.dialErr != nil {
		return nil, u.dialErr
	}

	if u.Conn != nil {
		return u.Conn, nil
	}

	// Create a stub dial - actual implementation would be in wsc.go
	if u.forwarder != nil && u.forwarder.wsDialer != nil {
		conn, err := u.forwarder.wsDialer.DialUDP()
		if err != nil {
			u.dialErr = err
			return nil, u.dialErr
		}
		u.Conn = conn.(net.Conn)
		// 检查是否已经是 CryptoConn（由 compat/dialer.go 包装）
		// 如果是，则不再重复包装，避免双重封装导致协议不匹配
		if _, ok := u.Conn.(*utils.CryptoConn); !ok {
			u.needsFraming = isStreamConn(u.Conn)
			u.Conn = utils.NewCryptoConn(u.Conn, u.forwarder.cryptoManager, u.needsFraming)
		}
		u.framingCached.Store(true)
		return u.Conn, nil
	}
	u.dialErr = errors.New("no forwarder configured")
	return nil, u.dialErr
}

func (u *udpConnInfo) SetupWithEarlyData(
	earlyData []byte,
	earlyDataHeaderName string,
) (net.Conn, error) {
	u.dialLock.Lock()
	defer u.dialLock.Unlock()
	defer u.setUpDoneOnce.Do(func() {
		close(u.setUpDone)
	})

	if u.closed.Load() {
		return nil, net.ErrClosed
	}

	if u.dialErr != nil {
		return nil, u.dialErr
	}

	if u.Conn != nil {
		return u.Conn, nil
	}

	// Create a stub dial - actual implementation would be in wsc.go
	if u.forwarder != nil && u.forwarder.wsDialer != nil {
		// Encrypt early data if encryption is enabled
		dataToEncode := earlyData
		if u.forwarder.cryptoManager != nil {
			encrypted, err := u.forwarder.cryptoManager.Encrypt(dataToEncode)
			if err != nil {
				u.dialErr = fmt.Errorf("failed to encrypt early data: %w", err)
				return nil, u.dialErr
			}
			dataToEncode = encrypted
		}

		headers := http.Header{}
		headers.Set(earlyDataHeaderName, base64.StdEncoding.EncodeToString(dataToEncode))

		conn, err := u.forwarder.wsDialer.DialUDPWithHeaders(headers)
		if err != nil {
			u.dialErr = err
			return nil, u.dialErr
		}
		u.Conn = conn.(net.Conn)
		// 检查是否已经是 CryptoConn（由 compat/dialer.go 包装）
		// 如果是，则不再重复包装，避免双重封装导致协议不匹配
		if _, ok := u.Conn.(*utils.CryptoConn); !ok {
			u.needsFraming = isStreamConn(u.Conn)
			u.Conn = utils.NewCryptoConn(u.Conn, u.forwarder.cryptoManager, u.needsFraming)
		}
		u.framingCached.Store(true)
		return u.Conn, nil
	}

	u.dialErr = errors.New("no forwarder configured")
	return nil, u.dialErr
}

func (u *udpConnInfo) Read(b []byte) (int, error) {
	<-u.setUpDone

	if u.closed.Load() {
		return 0, net.ErrClosed
	}

	if u.dialErr != nil {
		return 0, u.dialErr
	}

	conn := u.Conn
	if conn == nil {
		return 0, errors.New("connection not initialized")
	}

	u.SetLastActive(time.Now())

	n, err := conn.Read(b)

	u.SetLastActive(time.Now())

	return n, err
}

func (u *udpConnInfo) Write(b []byte) (int, error) {
	<-u.setUpDone

	if u.closed.Load() {
		return 0, net.ErrClosed
	}

	if u.dialErr != nil {
		return 0, u.dialErr
	}

	conn := u.Conn
	if conn == nil {
		return 0, errors.New("connection not initialized")
	}

	u.SetLastActive(time.Now())

	err := conn.SetWriteDeadline(time.Now().Add(utils.DefaultWriteTimeout))
	if err != nil {
		return 0, err
	}

	// 已经统一使用 utils.CryptoConn 处理加密和帧封装
	n, err := conn.Write(b)

	if err != nil {
		return 0, err
	}

	u.SetLastActive(time.Now())

	return n, nil
}

func (u *udpConnInfo) GetLastActive() time.Time {
	return time.Unix(0, u.lastActive.Load())
}

func (u *udpConnInfo) SetLastActive(t time.Time) {
	u.lastActive.Store(t.UnixNano())
}

type Forwarder struct {
	log                    Logger
	tcpListener            net.Listener
	listenErr              error
	udpPool                *ants.Pool
	wsDialer               WebSocketDialer
	udpConn                *net.UDPConn
	onListened             chan struct{}
	shutdowned             chan struct{}
	bufferPool             *sync.Pool
	cryptoManager          CryptoManager
	udpEarlyDataHeaderName string
	listenAddr             string
	udpConns               rwmap.RWMap[string, *udpConnInfo]
	bufferSize             int
	udpPoolSize            int
	udpCleanupInterval     time.Duration
	udpIdleTimeout         time.Duration
	udpMaxEarlyDataSize    int
	onListenCloseOnce      sync.Once
	useSharedUDPPool       bool
	udpPoolPreAlloc        bool
	disableUDP             bool
	disableTCP             bool
	disableUDPEarlyData    bool
}

type ForwarderOption func(*Forwarder)

func WithLogger(logger Logger) ForwarderOption {
	return func(f *Forwarder) {
		f.log = logger
	}
}

func WithDisableTCP() ForwarderOption {
	return func(f *Forwarder) {
		f.disableTCP = true
	}
}

func WithDisableUDP() ForwarderOption {
	return func(f *Forwarder) {
		f.disableUDP = true
	}
}

func WithUDPPool(pool *ants.Pool) ForwarderOption {
	return func(f *Forwarder) {
		f.udpPool = pool
		f.useSharedUDPPool = pool != nil
	}
}

func WithUDPPoolSize(size int) ForwarderOption {
	return func(f *Forwarder) {
		f.udpPoolSize = size
	}
}

func WithUDPPoolPreAlloc(preAlloc bool) ForwarderOption {
	return func(f *Forwarder) {
		f.udpPoolPreAlloc = preAlloc
	}
}

func WithBufferSize(size int) ForwarderOption {
	return func(f *Forwarder) {
		f.bufferSize = size
	}
}

func WithUDPCleanupInterval(interval time.Duration) ForwarderOption {
	return func(f *Forwarder) {
		f.udpCleanupInterval = interval
	}
}

func WithUDPIdleTimeout(timeout time.Duration) ForwarderOption {
	return func(f *Forwarder) {
		f.udpIdleTimeout = timeout
	}
}

func WithDisableUDPEarlyData() ForwarderOption {
	return func(f *Forwarder) {
		f.disableUDPEarlyData = true
	}
}

func WithUDPEarlyDataHeaderName(name string) ForwarderOption {
	return func(f *Forwarder) {
		f.udpEarlyDataHeaderName = name
	}
}

func WithMaxEarlyDataSize(size int) ForwarderOption {
	return func(f *Forwarder) {
		f.udpMaxEarlyDataSize = size
	}
}

func WithCryptoManager(cm CryptoManager) ForwarderOption {
	return func(f *Forwarder) {
		f.cryptoManager = cm
	}
}

func NewForwarder(listenAddr string, wsDialer WebSocketDialer, opts ...ForwarderOption) *Forwarder {
	wf := &Forwarder{
		listenAddr: listenAddr,
		wsDialer:   wsDialer,
		onListened: make(chan struct{}),
		shutdowned: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(wf)
	}

	// 如果 Dialer 在 ConnectOption 中已配置加密，则自动使用
	type cryptoProvider interface{ CryptoManager() CryptoManager }
	if p, ok := wsDialer.(cryptoProvider); ok && wf.cryptoManager == nil {
		wf.cryptoManager = p.CryptoManager()
	}

	if wf.udpCleanupInterval == 0 {
		wf.udpCleanupInterval = DefaultUDPCleanupInterval
	}

	if wf.udpIdleTimeout == 0 {
		wf.udpIdleTimeout = DefaultUDPIdleTimeout
	}

	if wf.udpEarlyDataHeaderName == "" {
		wf.udpEarlyDataHeaderName = DefaultUDPEarlyDataHeaderName
	}

	if wf.udpMaxEarlyDataSize == 0 {
		wf.udpMaxEarlyDataSize = DefaultUDPMaxEarlyDataSize
	}

	if wf.udpPoolSize == 0 {
		wf.udpPoolSize = DefaultUDPPoolSize
	}

	if wf.bufferSize == 0 {
		wf.bufferSize = utils.DefaultBufferSize
	}

	// Ensure buffer is large enough for encrypted packets if encryption is enabled
	// Although here we don't know if encryption is enabled until run-time maybe?
	// But actually we are setting wf.bufferSize.
	if wf.bufferSize < utils.UDPBufferSize {
		wf.bufferSize = utils.UDPBufferSize
	}

	wf.bufferPool = utils.NewBufferPool(wf.bufferSize)

	wf.log = utils.NewSafeLoggerOrNull(wf.log)

	return wf
}

func (wf *Forwarder) cleanupUDPIdleConnections() {
	ticker := time.NewTicker(wf.udpCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			wf.udpConns.Range(func(key string, value *udpConnInfo) bool {
				if now.Sub(value.GetLastActive()) <= wf.udpIdleTimeout {
					return true
				}

				if wf.udpConns.CompareAndDelete(key, value) {
					value.Close()
				}

				return true
			})
		case <-wf.shutdowned:
			wf.udpConns.Range(func(key string, value *udpConnInfo) bool {
				if wf.udpConns.CompareAndDelete(key, value) {
					value.Close()
				}
				return true
			})

			return
		}
	}
}

func (wf *Forwarder) closeOnListened() {
	wf.onListenCloseOnce.Do(func() {
		close(wf.onListened)
	})
}

func (wf *Forwarder) OnListened() <-chan struct{} {
	return wf.onListened
}

func (wf *Forwarder) ListenErr() error {
	return wf.listenErr
}

func (wf *Forwarder) Shutdowned() <-chan struct{} {
	return wf.shutdowned
}

func (wf *Forwarder) ShutdownedBool() bool {
	select {
	case <-wf.shutdowned:
		return true
	default:
		return false
	}
}

var ErrBothTCPAndUDPDisabled = errors.New("both TCP and UDP are disabled")

func (wf *Forwarder) Serve() (err error) {
	defer wf.closeOnListened()
	defer close(wf.shutdowned)

	if wf.disableTCP && wf.disableUDP {
		return ErrBothTCPAndUDPDisabled
	}

	if !wf.disableTCP {
		ln, err := net.Listen("tcp", wf.listenAddr)
		if err != nil {
			wf.listenErr = fmt.Errorf("failed to start TCP listener: %w", err)
			return fmt.Errorf("failed to start TCP listener: %w", err)
		}

		wf.tcpListener = ln
	}

	if !wf.disableUDP {
		if !wf.useSharedUDPPool {
			if wf.udpPoolSize == 0 {
				wf.udpPoolSize = DefaultUDPPoolSize
			}

			udpPool, err := ants.NewPool(
				wf.udpPoolSize,
				ants.WithPreAlloc(wf.udpPoolPreAlloc),
				ants.WithNonblocking(true),
			)
			if err != nil {
				if wf.tcpListener != nil {
					wf.tcpListener.Close()
					wf.tcpListener = nil
				}

				wf.listenErr = fmt.Errorf("failed to create UDP worker pool: %w", err)

				return fmt.Errorf("failed to create UDP worker pool: %w", err)
			}

			wf.udpPool = udpPool
		}

		var udpAddr *net.UDPAddr

		udpAddr, err = net.ResolveUDPAddr("udp", wf.listenAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address: %w", err)
		}

		var udpConn *net.UDPConn

		udpConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			if wf.tcpListener != nil {
				wf.tcpListener.Close()
				wf.tcpListener = nil
			}

			wf.listenErr = fmt.Errorf("failed to start UDP listener: %w", err)

			return fmt.Errorf("failed to start UDP listener: %w", err)
		}

		wf.udpConn = udpConn

		go wf.cleanupUDPIdleConnections()
	}

	wf.closeOnListened()

	return wf.serve()
}

func (wf *Forwarder) serve() error {
	if !wf.disableTCP && !wf.disableUDP {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					err := wf.processUDP()
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return
						}

						wf.log.Errorf("Failed to process UDP: %v", err)
					}
				}
			}
		}()

		for {
			conn, err := wf.tcpListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return err
				}

				wf.log.Errorf("Failed to accept TCP connection: %v", err)

				continue
			}

			go wf.handleTCP(conn)
		}
	} else if !wf.disableTCP {
		for {
			conn, err := wf.tcpListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return err
				}

				wf.log.Errorf("Failed to accept TCP connection: %v", err)

				continue
			}

			go wf.handleTCP(conn)
		}
	} else {
		for {
			err := wf.processUDP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return err
				}

				wf.log.Errorf("Failed to process UDP: %v", err)
			}
		}
	}
}

func (wf *Forwarder) Close() error {
	wf.closeOnListened()

	var errs []error
	if wf.tcpListener != nil {
		err := wf.tcpListener.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if wf.udpConn != nil {
		err := wf.udpConn.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if !wf.useSharedUDPPool && wf.udpPool != nil {
		wf.udpPool.Release()
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing WsForwarder: %v", errs)
	}

	return nil
}

func (wf *Forwarder) handleTCP(conn net.Conn) {
	defer conn.Close()

	wsConn, err := wf.wsDialer.DialTCP()
	if err != nil {
		wf.log.Errorf("Failed to dial tunnel connection: %v", err)
		return
	}
	defer wsConn.Close()

	// Check if wsConn supports deadline interface
	wsConnWithDeadline, ok := wsConn.(deadlineWriter)
	if !ok {
		// If not, we skip deadline operations but still copy data
		wf.log.Warnf("Tunnel connection doesn't support deadlines, proceeding without them")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := utils.GetBuffer(wf.bufferPool)
		defer utils.PutBuffer(wf.bufferPool, buffer)
		defer conn.Close()
		defer wsConn.Close()

		if wsConnWithDeadline != nil {
			_, err := utils.CopyBufferWithWriteTimeout(wsConnWithDeadline, conn, *buffer, utils.DefaultWriteTimeout)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				wf.log.Warnf("Failed to copy data to tunnel: %v", err)
			}
		} else {
			// Fall back to simple copy
			_, err := io.Copy(wsConn, conn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				wf.log.Warnf("Failed to copy data to tunnel: %v", err)
			}
		}
	}()

	buffer := utils.GetBuffer(wf.bufferPool)
	defer utils.PutBuffer(wf.bufferPool, buffer)

	if wsConnWithDeadline != nil {
		_, err = utils.CopyBufferWithWriteTimeout(conn, wsConn, *buffer, utils.DefaultWriteTimeout)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			wf.log.Warnf("Failed to copy data to Target: %v", err)
		}
	} else {
		// Fall back to simple copy
		_, err = io.Copy(conn, wsConn)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			wf.log.Warnf("Failed to copy data to Target: %v", err)
		}
	}

	// Wait for the copy goroutine to finish
	wg.Wait()
}

func (wf *Forwarder) processUDP() error {
	buffer := utils.GetBuffer(wf.bufferPool)

	n, remoteAddr, err := wf.udpConn.ReadFromUDP(*buffer)
	if err != nil {
		utils.PutBuffer(wf.bufferPool, buffer)
		return fmt.Errorf("failed to read from UDP: %w", err)
	}

	if err := wf.udpPool.Submit(func() {
		defer utils.PutBuffer(wf.bufferPool, buffer)

		key := remoteAddr.String()
		connInfo := getUDPConnInfo()
		connInfo.forwarder = wf

		value, loaded := wf.udpConns.LoadOrStore(key, connInfo)
		if !loaded {
			if wf.cryptoManager != nil && n <= wf.udpMaxEarlyDataSize {
				// Handle First Packet / Early Data
				dataCopy := make([]byte, n)
				copy(dataCopy, (*buffer)[:n])
				go func() {
					_, err := value.SetupWithEarlyData(dataCopy, DefaultUDPEarlyDataHeaderName)
					if err != nil {
						wf.log.Errorf("Failed to setup UDP connection with early data: %v", err)
						wf.udpConns.Delete(key)
						return
					}
					go wf.handleUDPResponse(value, remoteAddr)
				}()
				return
			} else if !wf.disableUDPEarlyData && n <= wf.udpMaxEarlyDataSize {
				if _, err := value.SetupWithEarlyData((*buffer)[:n], wf.udpEarlyDataHeaderName); err != nil {
					wf.log.Errorf("Failed to setup new UDP in websocket connection: %v", err)
					wf.udpConns.CompareAndDelete(key, value)
					return
				}

				go wf.handleUDPResponse(value, remoteAddr)

				// Early data already sent, no need to write again
				return
			}

			if _, err := value.Setup(); err != nil {
				wf.log.Errorf("Failed to setup new UDP in websocket connection: %v", err)
				wf.udpConns.CompareAndDelete(key, value)
				return
			}

			go wf.handleUDPResponse(value, remoteAddr)
		} else {
			connInfo.forwarder = nil
			putUDPConnInfo(connInfo)

			// Wait for setup to complete and check for errors
			<-value.setUpDone
			if value.dialErr != nil {
				wf.log.Errorf("UDP connection has setup error: %v", value.dialErr)
				wf.udpConns.CompareAndDelete(key, value)
				return
			}
		}

		// Write data (CryptoConn will handle encryption internally if configured)
		dataToWrite := (*buffer)[:n]
		_, err := value.Write(dataToWrite)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				wf.udpConns.CompareAndDelete(key, value)
				return
			}

			wf.log.Errorf("Failed to write to UDP in websocket connection: %v", err)

			if wf.udpConns.CompareAndDelete(key, value) {
				value.Close()
			}
		}
	}); err != nil {
		utils.PutBuffer(wf.bufferPool, buffer)
		if !errors.Is(err, ants.ErrPoolOverload) {
			wf.log.Errorf("Failed to submit UDP task: %v", err)
		}
	}

	return nil
}

func (wf *Forwarder) handleUDPResponse(value *udpConnInfo, remoteAddr *net.UDPAddr) {
	bufferP := utils.GetBuffer(wf.bufferPool)
	defer func() {
		utils.PutBuffer(wf.bufferPool, bufferP)

		if wf.udpConns.CompareAndDelete(remoteAddr.String(), value) {
			value.Close()
		}
		putUDPConnInfo(value)
	}()

	buffer := *bufferP

	for {
		// CryptoConn 已经统一处理了帧解封装和解密
		n, err := value.Read(buffer)

		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			if !errors.Is(err, io.EOF) {
				wf.log.Errorf("Failed to read from tunnel connection: %v", err)
			}

			return
		}

		if n == 0 {
			continue
		}

		// 写入本地 UDP 端口
		err = wf.udpConn.SetWriteDeadline(time.Now().Add(utils.DefaultWriteTimeout))
		if err != nil {
			wf.log.Errorf("Failed to set write deadline: %v", err)
			return
		}

		_, err = wf.udpConn.WriteToUDP(buffer[:n], remoteAddr)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			wf.log.Errorf("Failed to write to local UDP: %v", err)
			return
		}

		value.SetLastActive(time.Now())
	}
}

// isStreamConn 检查连接是否是流式连接（TCP/QUIC），而不是 WebSocket
func isStreamConn(conn net.Conn) bool {
	return utils.IsStreamConn(conn)
}

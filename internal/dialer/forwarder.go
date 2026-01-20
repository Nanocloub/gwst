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
	return sharedUDPConnInfoPool.Get().(*udpConnInfo)
}

func putUDPConnInfo(u *udpConnInfo) {
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

	u.setUpDoneOnce.Do(func() {
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
		headers := http.Header{}
		headers.Set(earlyDataHeaderName, base64.StdEncoding.EncodeToString(earlyData))

		conn, err := u.forwarder.wsDialer.DialUDPWithHeaders(headers)
		if err != nil {
			u.dialErr = err
			return nil, u.dialErr
		}
		u.Conn = conn.(net.Conn)
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

	if wf.bufferSize == 0 {
		wf.bufferSize = utils.DefaultBufferSize
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
		wf.log.Errorf("Failed to dial WebSocket: %v", err)
		return
	}
	defer wsConn.Close()

	// Check if wsConn supports deadline interface
	wsConnWithDeadline, ok := wsConn.(deadlineWriter)
	if !ok {
		// If not, we skip deadline operations but still copy data
		wf.log.Warnf("WebSocket connection doesn't support deadlines, proceeding without them")
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
			_, err := wf.copyWithEncryption(wsConnWithDeadline, conn, *buffer)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				wf.log.Warnf("Failed to copy data to WebSocket: %v", err)
			}
		} else {
			// Fall back to simple copy without encryption
			_, err := io.Copy(wsConn, conn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				wf.log.Warnf("Failed to copy data to WebSocket: %v", err)
			}
		}
	}()

	buffer := utils.GetBuffer(wf.bufferPool)
	defer utils.PutBuffer(wf.bufferPool, buffer)

	if wsConnWithDeadline != nil {
		_, err = wf.copyWithDecryption(conn, wsConn, *buffer)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			wf.log.Warnf("Failed to copy data to Target: %v", err)
		}
	} else {
		// Fall back to simple copy without decryption
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

	err = wf.udpPool.Submit(func() {
		defer utils.PutBuffer(wf.bufferPool, buffer)

		key := remoteAddr.String()
		connInfo := getUDPConnInfo()
		connInfo.forwarder = wf

		value, loaded := wf.udpConns.LoadOrStore(key, connInfo)
		if !loaded {
			if !wf.disableUDPEarlyData && n <= wf.udpMaxEarlyDataSize {
				if _, err := value.SetupWithEarlyData((*buffer)[:n], wf.udpEarlyDataHeaderName); err != nil {
					wf.log.Errorf("Failed to setup new UDP in websocket connection: %v", err)
					wf.udpConns.CompareAndDelete(key, value)
					return
				}

				go wf.handleUDPResponse(value, remoteAddr)

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
		}

		_, err := value.Write((*buffer)[:n])
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
	})
	if err != nil {
		utils.PutBuffer(wf.bufferPool, buffer)

		if errors.Is(err, ants.ErrPoolOverload) {
			wf.log.Errorf("UDP pool is overloaded, dropping packet: %v", remoteAddr.String())
		} else {
			wf.log.Errorf("Failed to submit UDP task: %v", err)
		}
	}

	return nil
}

// copyWithEncryption copies data from src to dst, encrypting if crypto manager is available
func (wf *Forwarder) copyWithEncryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	return utils.CopyWithEncryption(dst, src, buf, wf.cryptoManager, utils.DefaultWriteTimeout)
}

// copyWithDecryption copies data from src to dst, decrypting if crypto manager is available
func (wf *Forwarder) copyWithDecryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	return utils.CopyWithDecryption(dst, src, buf, wf.cryptoManager, utils.DefaultWriteTimeout)
}

func (wf *Forwarder) handleUDPResponse(value *udpConnInfo, remoteAddr *net.UDPAddr) {
	bufferP := utils.GetBuffer(wf.bufferPool)
	defer func() {
		utils.PutBuffer(wf.bufferPool, bufferP)

		if wf.udpConns.CompareAndDelete(remoteAddr.String(), value) {
			value.Close()
		}
	}()

	buffer := *bufferP

	for {
		n, err := value.Read(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			if !errors.Is(err, io.EOF) {
				wf.log.Errorf("Failed to read from WebSocket: %v", err)
			}

			return
		}

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

			wf.log.Errorf("Failed to write to UDP: %v", err)

			return
		}
	}
}

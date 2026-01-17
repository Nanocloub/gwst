package compat_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

func TestGenerateSelfSignedCertWithECC(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host, compat.WithECC())
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

func TestGenerateSelfSignedCertWithEd25519(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host, compat.WithEd25519())
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

func TestWsServerAndDialer(t *testing.T) {
	go func() {
		wss := compat.NewServer(
			"/ws",
			compat.NewHandler(
				compat.WithHandlerDefaultTargetAddr("127.0.0.1:8081"),
			),
			compat.WithListenAddr("0.0.0.0:8080"),
			compat.WithTLS("", ""),
			compat.WithServerName("www.microstft.com"),
			compat.WithSelfSignedCert(compat.WithECC()),
		)

		err := wss.Serve()
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		ln, err := net.Listen("tcp", "127.0.0.1:8081")
		if err != nil {
			panic(err)
		}
		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err != nil {
				panic(err)
			}

			fmt.Println("accepted tcp")

			go func(c net.Conn) {
				defer c.Close()

				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						panic(err)
					}

					fmt.Println("tcp", string(buf[:n]))
				}
			}(conn)
		}
	}()

	go func() {
		ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081})
		if err != nil {
			panic(err)
		}
		defer ln.Close()

		for {
			buf := make([]byte, 1024)

			n, _, err := ln.ReadFromUDP(buf)
			if err != nil {
				panic(err)
			}

			fmt.Println("udp", string(buf[:n]))
		}
	}()

	time.Sleep(time.Second * 2)

	go func() {
		wsc := compat.NewDialer(
			compat.WithAddr("127.0.0.1:8080"),
			compat.WithPath("/ws"),
			compat.WithDialTLS(true),
			compat.WithDialServerName("www.microstft.com"),
			compat.WithInsecure(true),
		)

		conn, err := wsc.DialTCP()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		fmt.Println("connected")

		for {
			_, err := conn.Write([]byte("hello"))
			if err != nil {
				panic(err)
			}

			time.Sleep(time.Second)
		}
	}()

	wsc := compat.NewDialer(
		compat.WithAddr("127.0.0.1:8080"),
		compat.WithPath("/ws"),
		compat.WithDialTLS(true),
		compat.WithDialServerName("www.microstft.com"),
		compat.WithInsecure(true),
	)

	conn, err := wsc.DialUDP()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("connected")

	for {
		_, err := conn.Write([]byte("hello"))
		if err != nil {
			panic(err)
		}

		time.Sleep(time.Second)
	}
}

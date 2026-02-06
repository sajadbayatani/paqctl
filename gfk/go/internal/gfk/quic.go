package gfk

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/SamNet-dev/paqctl/gfk/internal/config"
)

func RunQuicClient(ctx context.Context, cfg config.Config) error {
	log.Printf("QUIC client starting")

	udpAddr := &net.UDPAddr{IP: net.ParseIP(cfg.QUIC.LocalIP), Port: cfg.QUIC.ClientPort}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer pc.Close()

	remote := &net.UDPAddr{IP: net.ParseIP(cfg.QUIC.LocalIP), Port: cfg.VIO.UDPClientPort}
	if remote.IP == nil {
		return errors.New("invalid quic.local_ip")
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: !cfg.QUIC.VerifyCert,
		NextProtos:         []string{"gfk"},
		ServerName:         "gfk",
	}
	qconf := buildQuicConfig(cfg)

	sess, err := quic.Dial(ctx, pc, remote, tlsConf, qconf)
	if err != nil {
		return err
	}
	defer sess.CloseWithError(0, "client closing")

	tcpMappings, err := cfg.TCPMappings()
	if err != nil {
		return err
	}
	udpMappings, err := cfg.UDPMappings()
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	for lport, rport := range tcpMappings {
		laddr := net.JoinHostPort("0.0.0.0", itoa(lport))
		ln, err := net.Listen("tcp", laddr)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func(localPort, remotePort int) {
			defer wg.Done()
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				go handleTCPClient(ctx, sess, conn, cfg.QUIC.AuthCode, remotePort)
			}
		}(lport, rport)
	}

	for lport, rport := range udpMappings {
		wg.Add(1)
		go func(localPort, remotePort int) {
			defer wg.Done()
			err := runUDPClientListener(ctx, sess, cfg.QUIC.AuthCode, localPort, remotePort, time.Duration(cfg.QUIC.UDPTimeoutSec)*time.Second)
			if err != nil {
				log.Printf("udp listener error: %v", err)
			}
		}(lport, rport)
	}

	select {
	case <-ctx.Done():
		wg.Wait()
		return nil
	case <-sess.Context().Done():
		wg.Wait()
		return errors.New("quic connection closed")
	}
}

func RunQuicServer(ctx context.Context, cfg config.Config) error {
	log.Printf("QUIC server starting")

	cert, err := tls.LoadX509KeyPair(cfg.QUIC.CertFile, cfg.QUIC.KeyFile)
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"gfk"},
	}
	qconf := buildQuicConfig(cfg)

	addr := net.JoinHostPort("0.0.0.0", itoa(cfg.QUIC.ServerPort))
	ln, err := quic.ListenAddr(addr, tlsConf, qconf)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		sess, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handleQuicSession(ctx, sess, cfg)
	}
}

func handleQuicSession(ctx context.Context, sess quic.Connection, cfg config.Config) {
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go handleQuicStream(ctx, stream, cfg)
	}
}

func handleQuicStream(ctx context.Context, stream quic.Stream, cfg config.Config) {
	proto, port, leftover, err := readHeader(stream, cfg.QUIC.AuthCode)
	if err != nil {
		_ = stream.Close()
		return
	}

	switch proto {
	case "tcp":
		addr := net.JoinHostPort(cfg.XrayServerIPAddress, itoa(port))
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			_ = stream.Close()
			return
		}
		_, _ = stream.Write(buildReadyHeader(cfg.QUIC.AuthCode))
		if len(leftover) > 0 {
			_, _ = conn.Write(leftover)
		}
		pipeBidirectional(stream, conn)
	case "udp":
		addr := &net.UDPAddr{IP: net.ParseIP(cfg.XrayServerIPAddress), Port: port}
		if addr.IP == nil {
			_ = stream.Close()
			return
		}
		udpConn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			_ = stream.Close()
			return
		}
		if len(leftover) > 0 {
			_, _ = udpConn.Write(leftover)
		}
		pipeUDPStream(ctx, stream, udpConn)
	default:
		_ = stream.Close()
	}
}

func handleTCPClient(ctx context.Context, sess quic.Connection, conn net.Conn, auth string, remotePort int) {
	defer conn.Close()
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	_, _ = stream.Write(buildConnectHeader(auth, "tcp", remotePort))
	if err := readReady(stream, auth); err != nil {
		_ = stream.Close()
		return
	}
	pipeBidirectional(stream, conn)
}

func runUDPClientListener(ctx context.Context, sess quic.Connection, auth string, localPort, remotePort int, timeout time.Duration) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: localPort})
	if err != nil {
		return err
	}
	defer udpConn.Close()

	type udpStream struct {
		stream   quic.Stream
		lastSeen time.Time
	}

	mu := &sync.Mutex{}
	streams := make(map[string]*udpStream)

	cleanup := func() {
		if timeout == 0 {
			return
		}
		ticker := time.NewTicker(timeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for k, s := range streams {
					if time.Since(s.lastSeen) > timeout {
						_ = s.stream.Close()
						delete(streams, k)
					}
				}
				mu.Unlock()
			}
		}
	}

	go cleanup()

	buf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return err
		}
		key := addr.String()
		payload := append([]byte(nil), buf[:n]...)

		mu.Lock()
		st, ok := streams[key]
		if !ok {
			stream, err := sess.OpenStreamSync(ctx)
			if err != nil {
				mu.Unlock()
				return err
			}
			_, _ = stream.Write(buildConnectHeader(auth, "udp", remotePort))
			st = &udpStream{stream: stream, lastSeen: time.Now()}
			streams[key] = st
			go func(localAddr *net.UDPAddr, qs quic.Stream) {
				defer qs.Close()
				buf := make([]byte, 65535)
				for {
					n, err := qs.Read(buf)
					if n > 0 {
						_, _ = udpConn.WriteToUDP(buf[:n], localAddr)
					}
					if err != nil {
						return
					}
				}
			}(addr, stream)
		}
		st.lastSeen = time.Now()
		mu.Unlock()

		_, _ = st.stream.Write(payload)
	}
}

func pipeBidirectional(stream quic.Stream, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, conn)
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, stream)
		_ = conn.Close()
	}()
	wg.Wait()
}

func pipeUDPStream(ctx context.Context, stream quic.Stream, conn *net.UDPConn) {
	defer stream.Close()
	defer conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(buf)
			if n > 0 {
				_, _ = stream.Write(buf[:n])
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func buildQuicConfig(cfg config.Config) *quic.Config {
	conf := &quic.Config{}
	if cfg.QUIC.IdleTimeoutSec > 0 {
		conf.MaxIdleTimeout = time.Duration(cfg.QUIC.IdleTimeoutSec) * time.Second
	}
	conf.KeepAlivePeriod = 30 * time.Second
	if cfg.QUIC.MaxData > 0 {
		conf.MaxConnectionReceiveWindow = uint64(cfg.QUIC.MaxData)
	}
	if cfg.QUIC.MaxStreamData > 0 {
		conf.MaxStreamReceiveWindow = uint64(cfg.QUIC.MaxStreamData)
	}
	return conf
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

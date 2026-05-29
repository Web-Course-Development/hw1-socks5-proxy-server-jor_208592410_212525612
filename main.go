package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	socks5Version = 0x05
	authVersion   = 0x01

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}
	if method == methodNoAcceptable {
		return
	}
	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	host, port, err := readConnectRequest(conn)
	if err != nil {
		return
	}

	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = sendReply(conn, dialErrorToRep(err))
		return
	}
	defer target.Close()

	if err := sendReply(conn, repSuccess); err != nil {
		return
	}

	relay(conn, target)
}

// negotiateAuth reads the client greeting and writes the server's method
// selection. Returns the chosen method (or 0xFF when no method is acceptable).
func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != socks5Version {
		return 0, errors.New("unsupported socks version")
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return methodNoAcceptable, nil
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	required := requiredMethod()
	for _, m := range methods {
		if m == required {
			if _, err := conn.Write([]byte{socks5Version, required}); err != nil {
				return 0, err
			}
			return required, nil
		}
	}

	_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
	return methodNoAcceptable, nil
}

// requiredMethod picks the auth method the server will accept based on env.
// If PROXY_USER is set the server requires username/password; otherwise no-auth.
func requiredMethod() byte {
	if os.Getenv("PROXY_USER") != "" {
		return methodUserPass
	}
	return methodNoAuth
}

// authenticateUserPass implements the RFC 1929 sub-negotiation. The
// sub-negotiation version is 0x01 (NOT 0x05).
func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return errors.New("bad auth version")
	}
	ulen := int(header[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	passwd := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(uname) == expectedUser && string(passwd) == expectedPass {
		if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
			return err
		}
		return nil
	}

	_, _ = conn.Write([]byte{authVersion, 0x01})
	return errors.New("invalid credentials")
}

// readConnectRequest parses the SOCKS5 request and returns the target host
// (as IP literal or domain) and port. On a recognized but unsupported command
// or address type it sends the appropriate REP back to the client.
func readConnectRequest(conn net.Conn) (string, uint16, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socks5Version {
		_ = sendReply(conn, repGeneralFailure)
		return "", 0, errors.New("bad version in request")
	}
	if header[1] != cmdConnect {
		_ = sendReply(conn, repCmdNotSupported)
		return "", 0, errors.New("unsupported command")
	}

	var host string
	switch header[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case atypIPv6:
		_ = sendReply(conn, repAtypNotSupported)
		return "", 0, errors.New("ipv6 not supported")
	default:
		_ = sendReply(conn, repAtypNotSupported)
		return "", 0, errors.New("unknown address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

// sendReply writes a SOCKS5 reply with a zeroed IPv4 BND.ADDR and BND.PORT.
func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// dialErrorToRep maps a net.Dial error to a SOCKS5 REP code.
func dialErrorToRep(err error) byte {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") {
		return repConnRefused
	}
	if strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "unreachable") ||
		strings.Contains(msg, "no route") {
		return repHostUnreachable
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var dnsErr *net.DNSError
		if errors.As(opErr.Err, &dnsErr) {
			return repHostUnreachable
		}
	}
	return repGeneralFailure
}

// relay copies bytes in both directions between client and target. Each
// direction runs in its own goroutine; we use CloseWrite when available so
// that EOF propagates and HTTP responses can terminate cleanly.
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		closeWrite(target)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		closeWrite(client)
	}()

	wg.Wait()
}

// closeWrite half-closes the write side of conn if supported.
func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

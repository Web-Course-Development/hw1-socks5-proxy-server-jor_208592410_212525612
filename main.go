package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socks5Version      = 0x05
	authVersion        = 0x01
	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF
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

	// TODO: Implement SOCKS5 protocol
	// 1. Read client greeting and negotiate authentication method
	// 2. Perform authentication if required (when PROXY_USER env var is set)
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
}

// TODO 1 read client greeting and negotiate authentication method
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
// If PROXY_USER is set, the server requires username/password; otherwise no-auth.
func requiredMethod() byte {
	if os.Getenv("PROXY_USER") != "" {
		return methodUserPass
	}
	return methodNoAuth
}

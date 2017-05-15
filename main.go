package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {

	port := flag.Int("port", 8888, "specify port to listen on")
	flag.Parse()

	log.Println("Listening on", *port)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Could not listen for connections: %v\n", err)
	}

	connCounter := 0

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Could not accept connection: %v\n", err)
		}
		go handle(conn, connCounter)
		connCounter++
	}
}

func handle(conn net.Conn, connId int) {
	s := socksConn{connId: connId, conn: conn}
	if err := s.handle(); err != nil {
		log.Printf("Error handling connection %d: %v\n", connId, err)
	}
}

type socksConn struct {
	connId int
	conn   net.Conn
}

const (
	VERSION_5        = 0x05
	NO_AUTH_REQUIRED = 0x00
)

func (s *socksConn) handle() error {
	defer s.conn.Close()

	header, err := s.read(2)
	if err != nil {
		return err
	}

	// SOCKS version
	if header[0] != VERSION_5 {
		return fmt.Errorf("header: socks version wrong. expected %x got %x", VERSION_5, header[0])
	}
	// NMETHODS
	if header[1] == 0 {
		return fmt.Errorf("header: no authentication methods defined")
	}

	// METHOD
	methods, err := s.read(int(header[1]))
	if err != nil {
		return err
	}

	if !hasNoAuthMethod(methods) {
		return fmt.Errorf("header: client did not request NO AUTHENTICATION REQUIRED (%x) method: % x", NO_AUTH_REQUIRED, methods)
	}

	// send NO_AUTH_REQUIRED response
	if err := s.write(VERSION_5, NO_AUTH_REQUIRED); err != nil {
		return err
	}

	return nil
}

func hasNoAuthMethod(methods []byte) bool {
	for _, m := range methods {
		if m == NO_AUTH_REQUIRED {
			return true
		}
	}
	return false
}

func (s *socksConn) write(data ...byte) error {
	n, err := s.conn.Write(data)
	if n < len(data) || err != nil {
		return fmt.Errorf("could not write to connection: %v", err)
	}
	return nil
}

func (s *socksConn) read(len int) ([]byte, error) {
	buf := make([]byte, len)
	n, err := s.conn.Read(buf)
	if n != len || err != nil {
		return nil, fmt.Errorf("could not read from connection %d: %v", s.connId, err)
	}
	return buf, nil
}

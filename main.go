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

const SOCKS_VERSION_5 = 0x05

func (s *socksConn) handle() error {
	defer s.conn.Close()

	header, err := s.read(2)
	if err != nil {
		return err
	}

	if header[0] != SOCKS_VERSION_5 {
		return fmt.Errorf("header: socks version wrong. expected %x got %x", SOCKS_VERSION_5, header[0])
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

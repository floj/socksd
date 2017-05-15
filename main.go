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
	conn, err := listener.Accept()
	if err != nil {
		log.Printf("Could not accept connection: %v\n", err)
	}

	connCounter := 0

	go func() {
		handleConn(conn, connCounter)
		connCounter++
	}()

}

func handleConn(conn net.Conn, connId int) error {
	return nil
}

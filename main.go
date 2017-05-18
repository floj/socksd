package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/hashicorp/logutils"
)

func main() {

	var minLevel string
	var port int

	flag.StringVar(&minLevel, "loglevel", "WARN", "minimal log level to output")
	flag.IntVar(&port, "port", 8888, "specify port to listen on")
	flag.Parse()

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel(minLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	log.Printf("Listening on %d\n", port)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		errorLog("Could not listen for connections: %v", err)
		os.Exit(1)
	}

	connCounter := 0

	for {
		conn, err := listener.Accept()
		if err != nil {
			errorLog("Could not accept connection: %v", err)
		}
		go handle(conn, connCounter)
		connCounter++
	}
}

func handle(conn net.Conn, connId int) {
	s := socksConn{connId: connId, clientConn: conn}
	if err := s.handle(); err != nil {
		errorLog("= %d error handling request: %v", connId, err)
	}
}

type socksConn struct {
	connId     int
	clientConn net.Conn
	svrConn    net.Conn
}

const (
	VERSION_5             = 0x05
	NO_AUTH_REQUIRED      = 0x00
	NO_ACCEPTABLE_METHODS = 0xFF
	CONNECT               = 0x01
	BIND                  = 0x02
	UDP_ASSOCIATE         = 0x03
	RESERVED              = 0x00
	ATYP_IP_V4            = 0x01
	ATYP_DOMAINNAME       = 0x03
	ATYP_IP_V6            = 0x04
	BUFFER_SIZE           = 1024
	CMD_SUCCESS           = 0x00
	CMD_HOST_UNREACHABLE  = 0x04
)

var (
	validCmds   = []byte{CONNECT, BIND, UDP_ASSOCIATE}
	validAtypes = []byte{ATYP_IP_V4, ATYP_DOMAINNAME, ATYP_IP_V6}
)

type atypdef struct {
	raw   []byte
	proto string
	addr  string
}

func debug(format string, params ...interface{}) {
	log.Printf("[DEBUG] "+format, params...)
}

func info(format string, params ...interface{}) {
	log.Printf("[INFO]  "+format, params...)
}

func errorLog(format string, params ...interface{}) {
	log.Printf("[ERROR] "+format, params...)
}

func (s *socksConn) handle() error {
	defer s.clientConn.Close()

	info("< %d reading header", s.connId)

	header, err := s.read(2)
	if err != nil {
		return err
	}

	// SOCKS version
	if header[0] != VERSION_5 {
		return fmt.Errorf("header: VER expected %x got %x", VERSION_5, header[0])
	}
	// NMETHODS
	if header[1] == 0 {
		return fmt.Errorf("header: NMETHODS zero")
	}

	// METHOD
	methods, err := s.read(int(header[1]))
	if err != nil {
		return err
	}

	if !hasNoAuthMethod(methods) {
		if err = s.write(VERSION_5, NO_ACCEPTABLE_METHODS); err != nil {
			return err
		}
		//TODO: reutrn nil instead since this is not a "real" errer/valid behaviour?
		return fmt.Errorf("header: METHODS must contain %x (NO AUTH REQUIRED): % x", NO_AUTH_REQUIRED, methods)
	}

	// send NO_AUTH_REQUIRED response
	if err := s.write(VERSION_5, NO_AUTH_REQUIRED); err != nil {
		return err
	}

	info("< %d reading request", s.connId)
	request, err := s.read(4)
	if err != nil {
		return err
	}

	if request[0] != VERSION_5 {
		return fmt.Errorf("connect: VER expected %x got %x", VERSION_5, request[0])
	}

	cmd := request[1]
	if bytes.IndexByte(validCmds, cmd) < 0 {
		return fmt.Errorf("connect: CMD expected do be one of (% x) got %x", validCmds, cmd)
	}

	if request[2] != RESERVED {
		return fmt.Errorf("connect: RSV expected %x got %x", RESERVED, request[2])
	}

	atyp := request[3]
	var atypfunc func(s *socksConn) (*atypdef, error)
	switch atyp {
	case ATYP_IP_V4:
		atypfunc = atypIp4
	case ATYP_DOMAINNAME:
		atypfunc = atypDomainname
	case ATYP_IP_V6:
		atypfunc = atypIp6
	default:
		return fmt.Errorf("connect: ATYP expected do be one of (% x) got %x", validAtypes, atyp)
	}

	def, err := atypfunc(s)
	if err != nil {
		return err
	}

	pbuf, err := s.read(2)
	if err != nil {
		return err
	}

	destPort := int(pbuf[0])<<8 | int(pbuf[1])
	dest := fmt.Sprintf("%s:%d", def.addr, destPort)

	resp := make([]byte, 0, 4+2+len(def.raw))
	resp = append(resp, request...)
	resp = append(resp, def.raw...)
	resp = append(resp, pbuf...)

	info("> %d connecting to %s", s.connId, dest)
	svrConn, err := net.Dial(def.proto, dest)
	if err != nil {
		resp[1] = CMD_HOST_UNREACHABLE
		if wErr := s.write(resp...); wErr != nil {
			return wErr
		}
		return fmt.Errorf("could not connect do destionation host: %v", err)
	}
	defer svrConn.Close()
	s.svrConn = svrConn

	resp[1] = CMD_SUCCESS
	if err = s.write(resp...); err != nil {
		return err
	}

	info("= %d forwading data %s <-> %s", s.connId, s.clientConn.RemoteAddr(), s.svrConn.RemoteAddr())
	forwardConn(s.clientConn, svrConn)

	info("= %d closing connections", s.connId)

	return nil
}

func forwardConn(src, dest net.Conn) {
	go copy(src, dest)
	copy(dest, src)
}

func copy(src, dest net.Conn) error {
	_, err := io.Copy(src, dest)
	if err == io.EOF {
		return nil
	}
	return err
}

func atypIp4(s *socksConn) (*atypdef, error) {
	bytes, err := s.read(4)
	if err != nil {
		return nil, err
	}
	def := &atypdef{raw: bytes, proto: "tcp4", addr: net.IP(bytes).String()}
	return def, nil
}
func atypIp6(s *socksConn) (*atypdef, error) {
	bytes, err := s.read(16)
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("[%s]", net.IP(bytes))
	def := &atypdef{raw: bytes, proto: "tcp6", addr: addr}
	return def, nil
}
func atypDomainname(s *socksConn) (*atypdef, error) {
	n, err := s.read(1)
	if err != nil {
		return nil, err
	}
	len := int(n[0])
	name, err := s.read(len)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 0, len+1)
	raw = append(raw, n[0])
	raw = append(raw, name...)

	def := &atypdef{raw: raw, proto: "tcp", addr: string(name)}
	return def, nil
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
	debug("> writing % x", data)
	n, err := s.clientConn.Write(data)
	if n < len(data) || err != nil {
		return fmt.Errorf("could not write to connection: %v", err)
	}
	return nil
}

func (s *socksConn) read(len int) ([]byte, error) {
	buf := make([]byte, len)
	n, err := s.clientConn.Read(buf)
	if n != len || err != nil {
		return nil, fmt.Errorf("could not read from connection %d: %v", s.connId, err)
	}
	debug("< read % x", buf)
	return buf, nil
}

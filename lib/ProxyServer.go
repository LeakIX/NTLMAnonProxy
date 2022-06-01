package lib

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

type ProxyServer struct {
	Cert tls.Certificate
	Host string
	Port string
}

func (ps *ProxyServer) Start() error {
	listen, err := net.Listen("tcp", net.JoinHostPort(ps.Host, ps.Port))
	if err != nil {
		return err
	}
	// close listener
	defer listen.Close()
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go ps.handleIncomingConn(conn)
	}
}

func (ps *ProxyServer) handleIncomingConn(conn net.Conn) {
	// store incoming data
	defer conn.Close()
	bufferedConnection := bufio.NewReader(conn)
	req, err := http.ReadRequest(bufferedConnection)
	if err != nil {
		log.Println(err)
		return
	}
	// Process incoming request
	var scheme = "http"
	var port = "80"
	if len(req.URL.Port()) > 0 {
		port = req.URL.Port()
	}
	// If connect, we upgrade the connection
	if req.Method == "CONNECT" {
		req.Body.Close()
		scheme = "https"
		if len(req.URL.Port()) == 0 {
			port = "443"
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nProxy-Agent: NTLMAnonProxy\r\n\r\n"))
		log.Println("trying handshake")
		conn = tls.Server(conn, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{ps.Cert},
			ServerName:         req.URL.Hostname(),
		})
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Handshake done")
		bufferedConnection = bufio.NewReader(conn)
		req, err = http.ReadRequest(bufferedConnection)
		if err != nil {
			log.Println(err)
			return
		}
	}
	// Got all we need , handle the request on upgraded client connection
	cleanIncomingReq(req, scheme, port)
	moreEvilRequest(req)
	proxyConnection := &ProxyConnection{
		ClientConn:           conn,
		ClientBufferedReader: bufferedConnection,
		HttpRequest:          req,
		Host:                 req.URL.Host,
		Port:                 port,
		Scheme:               scheme,
	}
	err = proxyConnection.ConnectRemote()
	if err != nil {
		log.Println(err)
		proxyConnection.WriteError(500, err)
		return
	}
	defer proxyConnection.Close()
	err = proxyConnection.DoReq()
	if err != nil {
		log.Println(err)
		proxyConnection.WriteError(503, err)
		return
	}
}

func cleanIncomingReq(req *http.Request, scheme, port string) {
	for _, rmHeader := range removeHeaders {
		req.Header.Del(rmHeader)
	}
	req.RequestURI = ""
	req.URL.Scheme = scheme
	_, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		req.URL.Host = net.JoinHostPort(req.Host, port)
	} else {
		req.URL.Host = req.Host
	}
	req.URL.RawPath = req.URL.Path
}

func moreEvilRequest(req *http.Request) {
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Client-IP", "127.0.0.1")
	req.Header.Set("Real-Client-IP", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
}

var removeHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Proxy-Connection",
	"Accept-Encoding",
}

package main

import (
	"crypto/tls"
	"github.com/LeakIX/NTLMAnonProxy/lib"
	"log"
	"net"
	"os"
)

const (
	HOST = "127.0.0.1"
	PORT = "8080"
	TYPE = "tcp"
)

func main() {
	// TODO : Make those configurable doesn't matter very much for a debugging proxy
	cert, _ := tls.LoadX509KeyPair("./cert.pem", "./key.pem")
	ps := &lib.ProxyServer{
		Cert: cert,
		Host: os.Args[1],
		Port: os.Args[2],
	}
	log.Printf("Starting NTLM HTTP proxy on %s", net.JoinHostPort(ps.Host, ps.Port))
	log.Fatal(ps.Start())
}

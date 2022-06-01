package lib

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/LeakIX/ntlmssp"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type ProxyConnection struct {
	ClientConn           net.Conn
	realRemoteConn       net.Conn
	RemoteConn           io.ReadWriteCloser
	ClientBufferedReader *bufio.Reader
	RemoteBufferedReader *bufio.Reader
	HttpRequest          *http.Request
	Host                 string
	Port                 string
	Scheme               string
}

func (pr *ProxyConnection) Close() {
	pr.RemoteConn.Close()
	pr.ClientConn.Close()
}

func (pr *ProxyConnection) ConnectRemote() (err error) {
	remoteConn, err := net.Dial("tcp", pr.HttpRequest.URL.Host)
	if err != nil {
		return err
	}
	if tcpConn, isTcp := remoteConn.(*net.TCPConn); isTcp {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(2 * time.Second)
	}
	if pr.Scheme == "https" {
		remoteConn = tls.Client(remoteConn, &tls.Config{InsecureSkipVerify: true, ServerName: pr.Host})
		err = remoteConn.(*tls.Conn).Handshake()
		if err != nil {
			return err
		}
	}
	var file io.ReadWriteCloser
	if debugDir := os.Getenv("DEBUG_DIR"); len(debugDir) > 0 {
		fileName := fmt.Sprintf("%s/%s.%s.log", debugDir, pr.HttpRequest.URL.Host, strconv.FormatInt(time.Now().UnixNano(), 10))
		file, err = os.Create(fileName)
		if err != nil {
			return err
		}
		pr.RemoteConn = NewReadWriterDumper(remoteConn, file)
	} else {
		pr.RemoteConn = remoteConn
	}
	pr.RemoteBufferedReader = bufio.NewReader(pr.RemoteConn)
	return nil
}

func (pr *ProxyConnection) DoReq() (err error) {
	// Keep copy of the body if we need to resend/upgrade the request later
	bodyCopy, _ := ioutil.ReadAll(pr.HttpRequest.Body)
	if len(bodyCopy) > 0 {
		pr.HttpRequest.Body = ioutil.NopCloser(bytes.NewReader(bodyCopy))
	}
	log.Printf("%s : Intercepted request", pr.HttpRequest.URL.String())
	err = pr.HttpRequest.Write(pr.RemoteConn)
	if err != nil {
		return err
	}
	resp, err := http.ReadResponse(pr.RemoteBufferedReader, nil)
	if err != nil {
		return err
	}
	for _, authMethod := range resp.Header.Values("Www-Authenticate") {
		if authMethod == "NTLM" {
			log.Printf("%s : Proposing NTLM, forcing ANONYMOUS auth", pr.HttpRequest.URL.String())
			// Discarding current resp body, we are not authed anyway
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// If we had a body in original request add it back
			if len(bodyCopy) > 0 {
				pr.HttpRequest.Body = ioutil.NopCloser(bytes.NewReader(bodyCopy))
			}
			resp, err = pr.DoAnonNTLMReq()
			if err != nil {
				return err
			}
		}
	}
	// Start replying to our client
	log.Println(resp.Status)
	_, err = pr.ClientConn.Write([]byte("HTTP/1.1 " + resp.Status + "\r\n"))
	if err != nil {
		return err
	}
	resp.Header.Set("Proxy-Server", "NTLMAnonProxy")
	err = resp.Header.Write(pr.ClientConn)
	if err != nil {
		return err
	}
	_, err = pr.ClientConn.Write([]byte("\r\n"))
	if resp.StatusCode == 101 {
		//bridge connection for webscoket
		resp.Body.Close()
		go io.Copy(pr.RemoteConn, pr.ClientBufferedReader)
		_, err = io.Copy(pr.ClientConn, pr.RemoteBufferedReader)
	} else if strings.ToLower(resp.Header.Get("Connection")) == "keep-alive" {
		// send the last body, then just bridge connection
		_, err = io.Copy(pr.ClientConn, resp.Body)
		resp.Body.Close()
		go io.Copy(pr.RemoteConn, pr.ClientBufferedReader)
		_, err = io.Copy(pr.ClientConn, pr.RemoteBufferedReader)
	} else {
		// Not keep alive, not web socket, send and close
		_, err = io.Copy(pr.ClientConn, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		return err
	}
	return nil
}

func (pr *ProxyConnection) DoAnonNTLMReq() (*http.Response, error) {
	// Good old anonymous request
	// Keep a copy of our body we'll need it for the final request
	bodyCopy, _ := ioutil.ReadAll(pr.HttpRequest.Body)
	if len(bodyCopy) > 0 {
		pr.HttpRequest.Body = ioutil.NopCloser(bytes.NewReader(bodyCopy))
	}
	ntlmsspClient, err := ntlmssp.NewClient(ntlmssp.SetCompatibilityLevel(3), ntlmssp.SetUserInfo("", ""))
	if err != nil {
		return nil, err
	}
	negoMsg, err := ntlmsspClient.Authenticate(nil, nil)
	if err != nil {
		return nil, err
	}
	base64NTLMPayload := base64.StdEncoding.EncodeToString(negoMsg)
	pr.HttpRequest.Header.Set("Authorization", "NTLM "+base64NTLMPayload)
	// Write request to the wire
	err = pr.HttpRequest.Write(pr.RemoteConn)
	// Read response
	resp, err := http.ReadResponse(pr.RemoteBufferedReader, nil)
	if err != nil {
		return nil, err
	}
	// Get Challenge from response
	ntlmChallengeHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(ntlmChallengeHeader, "NTLM ") {
		return nil, errors.New("NTLM failed")
	}
	ntlmChallenge, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ntlmChallengeHeader, "NTLM "))
	if err != nil {
		return nil, errors.New("NTLM failed")
	}
	log.Printf("%s : Received NTLM challenge", pr.HttpRequest.URL.String())
	// We still unauth at this point, no point getting the body
	io.Copy(io.Discard, resp.Body)
	ntlmAuthMsg, err := ntlmsspClient.Authenticate(ntlmChallenge, nil)
	if err != nil {
		return nil, err
	}
	base64NTLMPayload = base64.StdEncoding.EncodeToString(ntlmAuthMsg)
	if err != nil {
		return nil, err
	}
	pr.HttpRequest.Header.Set("Authorization", "NTLM "+base64NTLMPayload)
	// Add our body back to the final request
	if len(bodyCopy) > 0 {
		pr.HttpRequest.Body = ioutil.NopCloser(bytes.NewReader(bodyCopy))
	}
	err = pr.HttpRequest.Write(pr.RemoteConn)
	if err != nil {
		return nil, err
	}
	log.Printf("%s : Sent NTLM AUTH", pr.HttpRequest.URL.String())
	// Get response
	return http.ReadResponse(pr.RemoteBufferedReader, nil)
}

func (pr *ProxyConnection) WriteError(status int, err error) {
	headers := http.Header{}
	headers.Add("Server", "NTLMAnonProxy")
	body := bytes.NewBufferString(fmt.Sprintf("<html><h2>NTLMAnonProxyError</h2><pre>%s</pre></html>", err.Error()))
	resp := &http.Response{
		Status:        "Proxy error",
		StatusCode:    status,
		Proto:         "HTTP",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          ioutil.NopCloser(body),
		ContentLength: int64(body.Len()),
	}
	resp.Write(pr.ClientConn)
}

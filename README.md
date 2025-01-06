## NTLMAnonProxy

This proxy intercepts HTTP/HTTPS connections and upgrades NTLM connection with ANONYMOUS credentials.

## Install

```bash
$ go install github.com/LeakIX/NTLMAnonProxy@latest
```

## SSL/TLS Interception

The proxy will use the provided `key.pem` and `cert.pem` in the current directory for all connections, and do MITM.
Browser will warn about HTTPS connections being unsafe since we're using a self-signed certificates instead of the remote's.
Feel free to create your CA/import it and regen keys if you need it.

## Run proxy

```sh
$ ./NTLMAnonProxy 127.0.0.1 9999
2022/06/01 06:38:25 Starting NTLM HTTP proxy on 127.0.0.1:9999
2022/06/01 06:38:28 trying handshake
2022/06/01 06:38:28 Handshake done
2022/06/01 06:38:28 https://192.168.0.44:443/ : Intercepted request
2022/06/01 06:38:29 https://192.168.0.44:443/ : Proposing NTLM, forcing ANONYMOUS auth
2022/06/01 06:38:30 https://192.168.0.44:443/ : Received NTLM challenge
2022/06/01 06:38:30 https://192.168.0.44:443/ : Sent NTLM AUTH
2022/06/01 06:38:32 200 OK
```


## Example request

```sh
$ https_proxy=http://127.0.0.1:9999 curl -skv https://192.168.0.44/ > /dev/null
* Uses proxy env variable https_proxy == 'http://127.0.0.1:9999'
*   Trying 127.0.0.1:9999...
* Connected to 127.0.0.1 (127.0.0.1) port 9999 (#0)
* allocate connect buffer!
* Establish HTTP proxy tunnel to 192.168.0.44:443
> CONNECT 192.168.0.44:443 HTTP/1.1
> Host: 192.168.0.44:443
> User-Agent: curl/7.74.0
> Proxy-Connection: Keep-Alive
> 
< HTTP/1.1 200 OK
< Proxy-Agent: NTLMAnonProxy
< 
* Proxy replied 200 to CONNECT request
* CONNECT phase completed!
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* CONNECT phase completed!
* CONNECT phase completed!
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd
*  start date: May 30 19:07:10 2022 GMT
*  expire date: May 30 19:07:10 2023 GMT
*  issuer: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET / HTTP/1.1
> Host: 192.168.0.44
> User-Agent: curl/7.74.0
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Cache-Control: no-cache,no-store,must-revalidate
< Content-Length: 6559
< Content-Type: text/html
< Date: Wed, 01 Jun 2022 04:38:32 GMT
< Etag: "1d50c1410ead59f"
< Expires: 0
< Last-Modified: Thu, 16 May 2019 18:20:40 GMT
< Pragma: no-cache
< Proxy-Server: NTLMAnonProxy
< Server: Microsoft-HTTPAPI/2.0
< Set-Cookie: XSRF-TOKEN=22ada548-7e34-4feb-a1c7-ec978b592aeb; path=/; secure
< X-Frame-Options: sameorigin
< 
* Connection #0 to host 127.0.0.1 left intact
```

## Bonus feature

`DEBUG_DIR=./conns ./NTLMAnonProxy 127.0.0.1 9999` will store connections dump in `DEBUG_DIR`

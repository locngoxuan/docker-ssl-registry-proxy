package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var target string

func main() {
	port := flag.Int("port", 443, "specify port of service")
	cert := flag.String("cert", "./ssl/server.crt", "specify cert file")
	key := flag.String("key", "./ssl/server.key", "specify key file")
	tg := flag.String("target", "", "specify target of proxy")
	flag.Parse()

	if v := strings.TrimSpace(*tg); v == "" {
		log.Println("target is empty")
		os.Exit(1)
	}
	target = strings.TrimSpace(*tg)

	if v := strings.TrimSpace(*cert); v == "" {
		log.Println("cert is empty")
		os.Exit(1)
	}

	if v := strings.TrimSpace(*key); v == "" {
		log.Println("key is empty")
		os.Exit(1)
	}

	r := http.NewServeMux()
	r.HandleFunc("/", proxy)

	httpserver := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", *port),
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				//full ciphers
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				// TLS 1.3 cipher suites.
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatalln(httpserver.ListenAndServeTLS(*cert, *key))
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func appendHostToXForwardHeader(header http.Header, host string) {
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func printBodyRequest(r *http.Request) string {
	var b string
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil {
			b = string(body)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
	}
	return b
}

func proxy(wr http.ResponseWriter, req *http.Request) {
	wr.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	normalizedPath := strings.TrimSpace(req.URL.Path)
	if !strings.HasPrefix(normalizedPath, "/") {
		normalizedPath = "/" + normalizedPath
	}

	normalizedPath = target + normalizedPath
	_url, err := url.Parse(normalizedPath)
	if err != nil {
		http.Error(wr, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	/**
	http: Request.RequestURI can't be set in client requests.
	http://golang.org/src/pkg/net/http/client.go
	*/
	_url.RawQuery = req.URL.RawQuery
	req.URL = _url

	client := newHttpClient(300 * time.Second)
	req.RequestURI = ""
	delHopHeaders(req.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(wr, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	delHopHeaders(resp.Header)

	location := resp.Header.Get("Location")
	if strings.TrimSpace(location) != "" {
		resp.Header.Del("Location")
		location = strings.TrimPrefix(location, "http://")
		location = "https://" + location
		resp.Header.Set("Location", location)
	}
	//remove duplicated header
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(wr, resp.Body)
}

func newHttpClient(timeout time.Duration) http.Client {
	client := http.Client{
		Timeout: timeout,
	}
	return client
}

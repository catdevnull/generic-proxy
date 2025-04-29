package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/armon/go-socks5"
	"github.com/caarlos0/env/v6"
	"tailscale.com/net/proxymux"
)

type params struct {
	User            string `env:"PROXY_USER" envDefault:""`
	Password        string `env:"PROXY_PASSWORD" envDefault:""`
	Port            string `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn string `env:"ALLOWED_DEST_FQDN" envDefault:""`
}

// httpProxyHandler implements a basic HTTP proxy
type httpProxyHandler struct {
	auth     bool
	user     string
	password string
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check authentication if enabled
	if h.auth {
		user, pass, ok := r.BasicAuth()
		if !ok || user != h.user || pass != h.password {
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

func (h *httpProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

func (h *httpProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	// Working with app params
	cfg := params{}
	err := env.Parse(&cfg)
	if err != nil {
		log.Printf("%+v\n", err)
	}

	// Initialize socks5 config
	socks5conf := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	// Configure authentication if credentials are provided
	auth := false
	if cfg.User+cfg.Password != "" {
		auth = true
		creds := socks5.StaticCredentials{
			cfg.User: cfg.Password,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		socks5conf.AuthMethods = []socks5.Authenticator{cator}
	}

	if cfg.AllowedDestFqdn != "" {
		socks5conf.Rules = PermitDestAddrPattern(cfg.AllowedDestFqdn)
	}

	socks5Server, err := socks5.New(socks5conf)
	if err != nil {
		log.Fatal(err)
	}

	// Create base listener
	baseListener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatal(err)
	}

	// Split the listener for SOCKS5 and HTTP
	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(baseListener)

	// Create HTTP proxy handler
	httpProxy := &httpProxyHandler{
		auth:     auth,
		user:     cfg.User,
		password: cfg.Password,
	}

	// Start HTTP proxy server
	go func() {
		server := &http.Server{
			Handler: httpProxy,
		}
		if err := server.Serve(httpListener); err != nil {
			log.Printf("HTTP proxy server error: %v\n", err)
		}
	}()

	log.Printf("Proxy service listening on port %s (SOCKS5 and HTTP)\n", cfg.Port)

	// Start SOCKS5 server
	if err := socks5Server.Serve(socksListener); err != nil {
		log.Fatal(err)
	}
}

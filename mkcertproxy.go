// Package mkcertproxy configures an SSL reverse proxy, using mkcert to generate
// missing keys if necessary.
package mkcertproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var MkcertExe = "mkcert"

// MkCert runs mkcert to generate a cert for the config's Domain to the config's
// CertificateFile and KeyFile paths.
func MkCert(cfg *Config) error {
	cmd := exec.Command(MkcertExe,
		"-cert-file", cfg.CertificateFile,
		"-key-file", cfg.KeyFile,
		cfg.Domain)

	log.Println("$ " + strings.Join(cmd.Args, " "))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	log.Println(string(out))
	return nil
}

// Config contains all of the properties needed to configure a Server.
type Config struct {
	// Domain specifies the reverse proxy server's SSL certificate's host name.
	Domain string

	// CertificateFile specifies the relative file path to the server's
	// certificate.
	CertificateFile string

	// KeyFile specifies the relative file path to the server's private key.
	KeyFile string

	// ListenPort specifies the local port the reverse proxy server listens on.
	ListenPort int

	// ProxyAddr specifies the scheme, host, and path of the reverse proxy's
	// target. The default scheme is "http://".
	ProxyAddr string

	// MakeCerts is an optional function that creates the certificate and key
	// files. If unset, MkCert is used as the default.
	MakeCerts func(*Config) error
}

// SetHostAndListenAddr sets the Domain, CertificateFile, KeyFile, and
// ListenAddr properties for the config based on the given cert directory and
// listen host:port value. certdir specifies where the certificate files should
// exist. If they don't, MakeCerts or MkCert will be called to create them.
func (cfg *Config) SetHostAndListenAddr(certdir, listen string) error {
	if cfg == nil {
		return errors.New("Config is nil")
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}

	num, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	cfg.ListenPort = num
	if len(host) == 0 {
		return nil
	}

	cfg.Domain = host

	useMkcert := false
	if len(cfg.CertificateFile) == 0 {
		cfg.CertificateFile = filepath.Join(certdir, host+".pem")
		info, err := os.Stat(cfg.CertificateFile)
		if err != nil {
			useMkcert = true
		}
		if info != nil && info.IsDir() {
			return fmt.Errorf("certfile %q is a directory", cfg.CertificateFile)
		}
	}

	if len(cfg.KeyFile) == 0 {
		cfg.KeyFile = filepath.Join(certdir, host+"-key.pem")
		info, err := os.Stat(cfg.KeyFile)
		if err != nil {
			useMkcert = true
		}
		if info != nil && info.IsDir() {
			return fmt.Errorf("keyfile %q is a directory", cfg.KeyFile)
		}
	}

	if useMkcert {
		return cfg.makeCerts()
	}

	return nil
}

func (cfg *Config) makeCerts() error {
	cb := cfg.MakeCerts
	if cb == nil {
		cb = MkCert
	}
	return cb(cfg)
}

// Server embeds http.Server and the httputil.ReverseProxy that the Server uses
// as its Handler.
type Server struct {
	*http.Server

	ReverseProxy *httputil.ReverseProxy
}

var reScheme = regexp.MustCompile(`\A[a-z]+\:\/\/`)

// New creates a new Server from the given Config.
func New(cfg *Config) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	proxyAddr := cfg.ProxyAddr
	if !reScheme.MatchString(proxyAddr) {
		proxyAddr = "http://" + proxyAddr
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	if len(proxyURL.Scheme) == 0 {
		proxyURL.Scheme = "http"
	}

	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	return &Server{
		Server: &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.ListenPort),
			Handler: proxy,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
		ReverseProxy: proxy,
	}, nil
}

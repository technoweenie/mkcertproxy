package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/technoweenie/mkcertproxy"
)

func main() {
	cfg := &mkcertproxy.Config{}
	listenFlag := flag.String("listen", "",
		"host:port for the server to listen to")
	certdirFlag := flag.String("certdir", "",
		"directory to find ")
	flag.StringVar(&cfg.CertificateFile,
		"cert", "", "location of ssl certificate file")
	flag.StringVar(&cfg.KeyFile,
		"key", "", "location of ssl key file")
	flag.StringVar(&cfg.ProxyAddr,
		"proxy", "", "server url to receive reverse proxy requests. Defaults to http://")
	flag.Parse()

	if err := cfg.SetHostAndListenAddr(*certdirFlag, *listenFlag); err != nil {
		log.Fatal(err)
	}

	srv, err := mkcertproxy.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if len(cfg.Domain) > 0 {
		log.Printf("LISTEN        https://%s%s", cfg.Domain, cfg.ListenAddr)
	} else {
		log.Printf("LISTEN        %s", cfg.ListenAddr)
	}

	log.Printf("REVERSE PROXY %s", cfg.ProxyAddr)
	log.Printf("CERT FILE     %s", cfg.CertificateFile)
	log.Printf("KEY FILE      %s", cfg.KeyFile)

	srv.ReverseProxy.ModifyResponse = func(res *http.Response) error {
		log.Printf("%d %9s %s",
			res.StatusCode,
			res.Request.Method,
			res.Request.URL.String(),
		)
		return nil
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

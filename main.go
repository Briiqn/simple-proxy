package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang/glog"
	"github.com/jthomperoo/simple-proxy/proxy"
)

var (
	Version = "development"
)

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "prints current simple-proxy version")
	var protocol string
	flag.StringVar(&protocol, "protocol", httpProtocol, "proxy protocol (http or https)")
	var bind string
	flag.StringVar(&bind, "bind", "0.0.0.0", "address to bind the proxy server to")
	var port string
	flag.StringVar(&port, "port", "8888", "proxy port to listen on")
	var certPath string
	flag.StringVar(&certPath, "cert", "", "path to cert file")
	var keyPath string
	flag.StringVar(&keyPath, "key", "", "path to key file")
	var basicAuth string
	flag.StringVar(&basicAuth, "basic-auth", "", "basic auth, format 'username:password', no auth if not provided")
	var logAuth bool
	flag.BoolVar(&logAuth, "log-auth", false, "log failed proxy auth details")
	var logHeaders bool
	flag.BoolVar(&logHeaders, "log-headers", false, "log request headers")
	var timeoutSecs int
	flag.IntVar(&timeoutSecs, "timeout", 10, "timeout in seconds")
	flag.Parse()

	if version {
		fmt.Println(Version)
		os.Exit(0)
	}

	if protocol != httpProtocol && protocol != httpsProtocol {
		glog.Fatalln("Protocol must be either http or https")
	}

	if protocol == httpsProtocol && (certPath == "" || keyPath == "") {
		glog.Fatalf("If using HTTPS protocol --cert and --key are required\n")
	}

	handler := proxy.NewProxyHandler(timeoutSecs)
	err := http.ListenAndServe("8080", handler)
	if err == nil {
		return
	}
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", bind, port),
		Handler:      handler,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	if protocol == httpProtocol {
		glog.V(0).Infoln("Starting HTTP proxy")
		log.Fatal(server.ListenAndServe())
	} else {
		glog.V(0).Infoln("Starting HTTPS")
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
	}
}

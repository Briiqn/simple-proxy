package main

import (
	"flag"
	"github.com/jthomperoo/simple-proxy/proxy"
	"log"
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
	username := "github"
	password := "test"
	server, err := proxy.NewProxyServer(":8888", ":1080", 30, &username, &password)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Proxy server error: %v", err)
	}
}

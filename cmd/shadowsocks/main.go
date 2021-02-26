package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/wzshiming/shadowsocks"
	_ "github.com/wzshiming/shadowsocks/init"
)

var address string
var cipher string
var password string

func init() {
	flag.StringVar(&address, "a", ":8379", "listen on the address")
	flag.StringVar(&cipher, "c", "chacha20-ietf-poly1305", fmt.Sprintf("cipher (%s)", strings.Join(shadowsocks.CipherList(), ", ")))
	flag.StringVar(&password, "p", "password", "your password")
	flag.Parse()
}

func main() {
	logger := log.New(os.Stderr, "[shadowsocks] ", log.LstdFlags)
	go func() {
		svc := &shadowsocks.Server{
			Logger:   logger,
			Cipher:   cipher,
			Password: password,
		}

		err := svc.ListenAndServe("tcp", address)
		if err != nil {
			logger.Println(err)
		}
		os.Exit(1)
	}()
	go func() {
		svc := &shadowsocks.PacketServer{
			Logger:   logger,
			Cipher:   cipher,
			Password: password,
		}

		err := svc.ListenAndServe("udp", address)
		if err != nil {
			logger.Println(err)
		}
		os.Exit(1)
	}()
	<-make(chan struct{})
}

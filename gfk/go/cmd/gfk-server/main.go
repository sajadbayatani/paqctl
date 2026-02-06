package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SamNet-dev/paqctl/gfk/internal/config"
	"github.com/SamNet-dev/paqctl/gfk/internal/gfk"
)

func main() {
	configPath := flag.String("config", "gfk.json", "Path to GFK config JSON")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("signal received, shutting down")
		cancel()
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- gfk.RunVIOServer(ctx, cfg) }()
	go func() { errCh <- gfk.RunQuicServer(ctx, cfg) }()

	err = <-errCh
	if err != nil {
		log.Printf("server error: %v", err)
	}
	cancel()
	<-errCh
}

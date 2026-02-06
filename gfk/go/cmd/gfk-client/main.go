package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	go func() { errCh <- gfk.RunVIOClient(ctx, cfg) }()
	go func() {
		var lastErr error
		for {
			if ctx.Err() != nil {
				errCh <- lastErr
				return
			}
			err := gfk.RunQuicClient(ctx, cfg)
			if err == nil || ctx.Err() != nil {
				errCh <- err
				return
			}
			lastErr = err
			log.Printf("quic client error: %v (retrying in 1s)", err)
			time.Sleep(1 * time.Second)
		}
	}()

	err = <-errCh
	if err != nil {
		log.Printf("client error: %v", err)
	}
	cancel()
	<-errCh
}

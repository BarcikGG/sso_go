package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/endl/sso_go/internal/app"
	"github.com/endl/sso_go/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := app.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.DB.Pool.Close()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--register-client":
			if len(os.Args) < 5 {
				return errors.New("usage: sso --register-client CLIENT_ID PROJECT_ID REDIRECT_URI... (secret in SSO_NEW_CLIENT_SECRET)")
			}
			return s.RegisterClient(ctx, os.Args[2], os.Args[3], os.Getenv("SSO_NEW_CLIENT_SECRET"), os.Args[4:])
		case "--rotate-key":
			return s.RotateKey(ctx)
		case "--grant-project-admin":
			if len(os.Args) != 4 {
				return errors.New("usage: sso --grant-project-admin PROJECT_ID VERIFIED_EMAIL")
			}
			return s.GrantProjectAdmin(ctx, os.Args[2], os.Args[3])
		case "--grant-global-admin":
			if len(os.Args) != 3 {
				return errors.New("usage: sso --grant-global-admin VERIFIED_EMAIL")
			}
			return s.GrantGlobalAdmin(ctx, os.Args[2])
		default:
			return errors.New("unknown command")
		}
	}
	if cfg.RotateKey {
		if err := s.RotateKey(ctx); err != nil {
			return err
		}
	}

	g, err := s.GRPC.GRPCServer()
	if err != nil {
		return err
	}
	grpcListener, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return err
	}
	httpListener, err := net.Listen("tcp", ":"+cfg.HTTPPort)
	if err != nil {
		grpcListener.Close()
		return err
	}
	h := &http.Server{Handler: s.HTTP.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- g.Serve(grpcListener) }()
	go func() { serveErrors <- h.Serve(httpListener) }()
	go s.PublishOutbox(ctx, cfg.KafkaBroker, cfg.KafkaTopic)
	go s.Cleanup(ctx)
	log.Printf("SSO HTTP :%s, gRPC :%s", cfg.HTTPPort, cfg.GRPCPort)

	select {
	case <-ctx.Done():
	case err = <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("SSO listener stopped: %v", err)
		}
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.Shutdown(shutdownCtx)
	grpcStopped := make(chan struct{})
	go func() { g.GracefulStop(); close(grpcStopped) }()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		g.Stop()
	}
	return err
}

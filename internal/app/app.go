package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/endl/sso_go/internal/auth"
	"github.com/endl/sso_go/internal/config"
	"github.com/endl/sso_go/internal/httpapi"
	"github.com/endl/sso_go/internal/store/memory"
	mysqlstore "github.com/endl/sso_go/internal/store/mysql"
)

type App struct {
	cfg        config.Config
	server     *http.Server
	mysqlStore *mysqlstore.AuthStore
}

func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	userStore, sessionStore, mysqlStore, err := buildStores(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	authService, err := auth.NewService(cfg, userStore, sessionStore)
	if err != nil {
		return nil, err
	}
	if err := authService.BootstrapAdmin(context.Background()); err != nil {
		return nil, err
	}

	router := httpapi.NewRouter(cfg, authService)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &App{
		cfg:        cfg,
		server:     server,
		mysqlStore: mysqlStore,
	}, nil
}

func (a *App) Run() error {
	return a.server.ListenAndServe()
}

func (a *App) Shutdown(ctx context.Context) error {
	if a.mysqlStore != nil {
		_ = a.mysqlStore.Close()
	}

	return a.server.Shutdown(ctx)
}

func buildStores(ctx context.Context, cfg config.Config) (auth.UserStore, auth.SessionStore, *mysqlstore.AuthStore, error) {
	if cfg.Database.URL == "" {
		store := memory.NewAuthStore()
		return store, store, nil, nil
	}

	switch cfg.Database.Driver {
	case "mysql":
		store, err := mysqlstore.New(ctx, cfg.Database)
		if err != nil {
			return nil, nil, nil, err
		}
		return store, store, store, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}
}

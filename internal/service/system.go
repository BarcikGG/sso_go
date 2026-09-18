package service

import (
	"context"

	"github.com/endl/sso_go/internal/repository/postgres"
)

type System struct{ Repo *postgres.DB }
type OutboxMetrics = postgres.OutboxMetrics

func (s System) Ready(ctx context.Context) error                    { return s.Repo.Pool.Ping(ctx) }
func (s System) Metrics(ctx context.Context) (OutboxMetrics, error) { return s.Repo.OutboxMetrics(ctx) }

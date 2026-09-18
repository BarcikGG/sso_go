package service

import (
	"context"
	"time"

	"github.com/endl/sso_go/internal/repository/postgres"
)

type Limits struct{ Repo *postgres.DB }

func (s Limits) Allow(ctx context.Context, scope, value string, limit int, window time.Duration) bool {
	if value == "" {
		return false
	}
	attempts, err := s.Repo.IncrementAttempt(ctx, postgres.Hash(scope+":"+value), time.Now().Add(window))
	return err == nil && attempts <= limit
}

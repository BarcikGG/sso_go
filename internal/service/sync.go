// Package service contains request-independent SSO use cases.
package service

import (
	"context"
	"crypto/subtle"

	"github.com/endl/sso_go/internal/repository/postgres"
)

type Sync struct{ Repo *postgres.DB }

func (s Sync) ClientProject(ctx context.Context, id, secret string) (string, error) {
	if id == "" || secret == "" {
		return "", ErrInvalidClient
	}
	client, err := s.Repo.Client(ctx, id)
	if postgres.IsNotFound(err) {
		return "", ErrInvalidClient
	}
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(postgres.Hash(secret))) != 1 {
		return "", ErrInvalidClient
	}
	return client.Project, nil
}

func (s Sync) Snapshot(ctx context.Context, project, after string, cursor *int64) (postgres.Snapshot, error) {
	return s.Repo.Snapshot(ctx, project, after, cursor)
}

func (s Sync) Changes(ctx context.Context, project string, after int64) ([]postgres.SyncEvent, int64, error) {
	return s.Repo.Changes(ctx, project, after)
}

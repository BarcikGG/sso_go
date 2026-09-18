package service

import (
	"errors"

	"github.com/endl/sso_go/internal/repository/postgres"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrRefreshReuse = errors.New("refresh token reuse")
)

func storageError(err error) error {
	if postgres.IsNotFound(err) {
		return ErrNotFound
	}
	if postgres.IsConflict(err) {
		return ErrConflict
	}
	return err
}

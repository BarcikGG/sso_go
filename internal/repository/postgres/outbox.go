package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

type OutboxEntry struct {
	ID, Project, Kind string
	Payload           json.RawMessage
}

// PublishNext holds the row lock through send. On failure it retains the row.
func (d *DB) PublishNext(ctx context.Context, send func(OutboxEntry) error) (bool, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var entry OutboxEntry
	err = tx.QueryRow(ctx, "SELECT id,project_id,event_type,payload FROM outbox WHERE published_at IS NULL ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED").Scan(&entry.ID, &entry.Project, &entry.Kind, &entry.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = send(entry); err != nil {
		if _, recordErr := tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1,last_error=$2 WHERE id=$1", entry.ID, err.Error()); recordErr != nil {
			return true, recordErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return true, commitErr
		}
		return true, err
	}
	if _, err = tx.Exec(ctx, "UPDATE outbox SET published_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1", entry.ID); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}

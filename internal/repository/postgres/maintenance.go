package postgres

import (
	"context"
	"time"
)

func (d *DB) IncrementAttempt(ctx context.Context, key string, until time.Time) (int, error) {
	var attempts int
	err := d.Pool.QueryRow(ctx, `INSERT INTO auth_limits(key_hash,attempts,window_until) VALUES($1,1,$2)
		ON CONFLICT(key_hash) DO UPDATE SET
		attempts=CASE WHEN auth_limits.window_until<now() THEN 1 ELSE auth_limits.attempts+1 END,
		window_until=CASE WHEN auth_limits.window_until<now() THEN $2 ELSE auth_limits.window_until END
		RETURNING attempts`, key, until).Scan(&attempts)
	return attempts, err
}

type OutboxMetrics struct {
	Pending, Retried int64
	OldestAgeSeconds float64
}

func (d *DB) OutboxMetrics(ctx context.Context) (OutboxMetrics, error) {
	var m OutboxMetrics
	err := d.Pool.QueryRow(ctx, "SELECT count(*),count(*) FILTER (WHERE attempts>0),coalesce(extract(epoch from now()-min(created_at)),0) FROM outbox WHERE published_at IS NULL").Scan(&m.Pending, &m.Retried, &m.OldestAgeSeconds)
	return m, err
}

func (d *DB) CleanupExpired(ctx context.Context) error {
	for _, query := range []string{
		"DELETE FROM auth_limits WHERE window_until < now() - interval '1 day'",
		"DELETE FROM email_verifications WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM password_resets WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM authorization_codes WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM browser_sessions WHERE expires_at < now()",
		"DELETE FROM refresh_tokens WHERE family_expires_at < now() - interval '1 day'",
		"DELETE FROM signing_keys WHERE publish_until < now() - interval '1 day'",
		"DELETE FROM outbox WHERE published_at < now() - interval '30 days'",
	} {
		if _, err := d.Pool.Exec(ctx, query); err != nil {
			return err
		}
	}
	return nil
}

package postgres

import (
	"context"
	"encoding/json"
)

func (d *DB) RotateSigningKey(ctx context.Context, kid string, private, public []byte) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(77213002)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE signing_keys SET retired_at=now(),publish_until=now()+interval '10 minutes' WHERE retired_at IS NULL"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO signing_keys(kid,private_pem,public_jwk) VALUES($1,$2,$3)", kid, private, public); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) ActiveSigningKey(ctx context.Context) (string, []byte, error) {
	var kid string
	var private []byte
	err := d.Pool.QueryRow(ctx, "SELECT kid,private_pem FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1").Scan(&kid, &private)
	return kid, private, err
}

func (d *DB) ActiveSigningKeyCount(ctx context.Context) (int, error) {
	var count int
	err := d.Pool.QueryRow(ctx, "SELECT count(*) FROM signing_keys WHERE retired_at IS NULL").Scan(&count)
	return count, err
}

func (d *DB) PublicSigningKeys(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := d.Pool.Query(ctx, "SELECT public_jwk FROM signing_keys WHERE retired_at IS NULL OR publish_until>now()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []json.RawMessage{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		keys = append(keys, raw)
	}
	return keys, rows.Err()
}

func (d *DB) VerificationKey(ctx context.Context, kid string) ([]byte, error) {
	var private []byte
	err := d.Pool.QueryRow(ctx, "SELECT private_pem FROM signing_keys WHERE kid=$1 AND (retired_at IS NULL OR publish_until>now())", kid).Scan(&private)
	return private, err
}

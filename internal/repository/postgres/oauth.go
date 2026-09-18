package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrRefreshReuse = errors.New("refresh token reuse detected")

type AuthorizationCode struct {
	Account, Client, Redirect, Nonce, Challenge string
	Scopes                                      []string
}

func (d *DB) CreateAuthorizationCode(ctx context.Context, hash string, code AuthorizationCode) error {
	_, err := d.Pool.Exec(ctx, "INSERT INTO authorization_codes(code_hash,account_id,client_id,redirect_uri,nonce,code_challenge,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '2 minutes')", hash, code.Account, code.Client, code.Redirect, code.Nonce, code.Challenge, code.Scopes)
	return err
}

// ConsumeAuthorizationCode commits the one-time use only after client, redirect and PKCE match.
func (d *DB) ConsumeAuthorizationCode(ctx context.Context, hash, client, redirect string, validChallenge func(string) bool) (AuthorizationCode, error) {
	var code AuthorizationCode
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return code, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "UPDATE authorization_codes SET used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING account_id,client_id,redirect_uri,nonce,code_challenge,scopes", hash).Scan(&code.Account, &code.Client, &code.Redirect, &code.Nonce, &code.Challenge, &code.Scopes)
	if err != nil {
		return code, err
	}
	if code.Client != client || code.Redirect != redirect || !validChallenge(code.Challenge) {
		return code, pgx.ErrNoRows
	}
	return code, tx.Commit(ctx)
}

type RefreshGrant struct {
	Account string
	Scopes  []string
}

func (d *DB) RotateRefresh(ctx context.Context, hash, nextHash, client, project string, now time.Time) (RefreshGrant, error) {
	var grant RefreshGrant
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return grant, err
	}
	defer tx.Rollback(ctx)
	var family, clientID, tokenProject string
	var expires, familyExpires time.Time
	var used, revoked *time.Time
	err = tx.QueryRow(ctx, "SELECT family_id,account_id,client_id,project_id,scopes,expires_at,family_expires_at,used_at,revoked_at FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE", hash).Scan(&family, &grant.Account, &clientID, &tokenProject, &grant.Scopes, &expires, &familyExpires, &used, &revoked)
	if err != nil {
		return grant, err
	}
	if clientID != client || tokenProject != project {
		return grant, pgx.ErrNoRows
	}
	if used != nil || revoked != nil {
		if _, err = tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL", family); err != nil {
			return grant, err
		}
		if err = tx.Commit(ctx); err != nil {
			return grant, err
		}
		return grant, ErrRefreshReuse
	}
	if !expires.After(now) || !familyExpires.After(now) {
		return grant, pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, "UPDATE refresh_tokens SET used_at=now() WHERE token_hash=$1", hash); err != nil {
		return grant, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO refresh_tokens(token_hash,family_id,account_id,client_id,project_id,scopes,expires_at,family_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)", nextHash, family, grant.Account, client, project, grant.Scopes, familyExpires); err != nil {
		return grant, err
	}
	return grant, tx.Commit(ctx)
}

func (d *DB) CreateRefresh(ctx context.Context, hash, family, account, client, project string, scopes []string) error {
	_, err := d.Pool.Exec(ctx, "INSERT INTO refresh_tokens(token_hash,family_id,account_id,client_id,project_id,scopes,expires_at,family_expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days',now()+interval '7 days')", hash, family, account, client, project, scopes)
	return err
}

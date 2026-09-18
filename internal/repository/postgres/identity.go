package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrInvalidPassword = errors.New("invalid password")

type PendingAccount struct {
	ID, Email, Login, PasswordHash, Name, GivenName, FamilyName, VerificationHash string
}

func (d *DB) CreatePendingAccount(ctx context.Context, a PendingAccount) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO accounts(id,email,login,password_hash,name,given_name,family_name,status) VALUES($1,$2,$3,$4,$5,$6,$7,'pending')", a.ID, a.Email, a.Login, a.PasswordHash, a.Name, a.GivenName, a.FamilyName); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO email_verifications(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", a.VerificationHash, a.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) UnverifiedAccountID(ctx context.Context, email string) (string, error) {
	var id string
	err := d.Pool.QueryRow(ctx, "SELECT id FROM accounts WHERE email=$1 AND email_verified_at IS NULL", email).Scan(&id)
	return id, err
}

func (d *DB) AddEmailVerification(ctx context.Context, account, hash string) error {
	_, err := d.Pool.Exec(ctx, "INSERT INTO email_verifications(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", hash, account)
	return err
}

func (d *DB) VerifyEmail(ctx context.Context, hash string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id string
	if err = tx.QueryRow(ctx, "UPDATE email_verifications SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING account_id", hash).Scan(&id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE accounts SET email_verified_at=now() WHERE id=$1", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type LoginAccount struct {
	ID, PasswordHash, Status string
	Verified                 *time.Time
}

// WithLogin holds the account row until the password check and session insert finish.
func (d *DB) WithLogin(ctx context.Context, identifier string, fn func(LoginAccount, func(string) error) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var a LoginAccount
	err = tx.QueryRow(ctx, "SELECT id,password_hash,email_verified_at,status FROM accounts WHERE email=$1 OR lower(login)=$1 FOR UPDATE", identifier).Scan(&a.ID, &a.PasswordHash, &a.Verified, &a.Status)
	if err != nil {
		return err
	}
	create := func(hash string) error {
		_, err := tx.Exec(ctx, "INSERT INTO browser_sessions(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '7 days')", hash, a.ID)
		return err
	}
	if err = fn(a, create); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) SessionAccount(ctx context.Context, tokenHash string) (string, error) {
	var id string
	err := d.Pool.QueryRow(ctx, "SELECT s.account_id FROM browser_sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>now() AND a.status<>'disabled'", tokenHash).Scan(&id)
	return id, err
}

func (d *DB) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := d.Pool.Exec(ctx, "DELETE FROM browser_sessions WHERE token_hash=$1", tokenHash)
	return err
}

type UserProject struct{ ID, Name, Status string }

func (d *DB) UserProjects(ctx context.Context, user string) ([]UserProject, error) {
	rows, err := d.Pool.Query(ctx, "SELECT p.id,p.name,CASE WHEN a.account_id IS NOT NULL THEN 'granted' ELSE coalesce(q.status,'none') END FROM projects p LEFT JOIN project_access a ON a.project_id=p.id AND a.account_id=$1 LEFT JOIN access_requests q ON q.project_id=p.id AND q.account_id=$1", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := []UserProject{}
	for rows.Next() {
		var p UserProject
		if err = rows.Scan(&p.ID, &p.Name, &p.Status); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (d *DB) RequestAccess(ctx context.Context, requestID, user, project string) error {
	_, err := d.Pool.Exec(ctx, "INSERT INTO access_requests(id,account_id,project_id) VALUES($1,$2,$3) ON CONFLICT(account_id,project_id) DO UPDATE SET status='pending',created_at=now(),decided_at=NULL WHERE access_requests.status<>'pending'", requestID, user, project)
	return err
}

func (d *DB) PasswordResetAccount(ctx context.Context, email string) (string, error) {
	var id string
	err := d.Pool.QueryRow(ctx, "SELECT id FROM accounts WHERE email=$1 AND email_verified_at IS NOT NULL AND status<>'disabled'", email).Scan(&id)
	return id, err
}

func (d *DB) AddPasswordReset(ctx context.Context, account, hash string) error {
	_, err := d.Pool.Exec(ctx, "INSERT INTO password_resets(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '20 minutes')", hash, account)
	return err
}

func (d *DB) revokePasswordSessions(ctx context.Context, tx pgx.Tx, id, hash string) error {
	for _, command := range []struct {
		sql  string
		args []any
	}{
		{"UPDATE accounts SET password_hash=$1,updated_at=now() WHERE id=$2", []any{hash, id}},
		{"DELETE FROM browser_sessions WHERE account_id=$1", []any{id}},
		{"UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND revoked_at IS NULL", []any{id}},
		{"DELETE FROM authorization_codes WHERE account_id=$1", []any{id}},
		{"DELETE FROM password_resets WHERE account_id=$1", []any{id}},
	} {
		if _, err := tx.Exec(ctx, command.sql, command.args...); err != nil {
			return err
		}
	}
	projects, err := d.ProfileProjects(ctx, tx, id, "")
	if err != nil {
		return err
	}
	for _, project := range projects {
		if err = d.QueueEvent(ctx, tx, project, "sessions.revoked", id, map[string]any{"user_id": id}); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) ResetPassword(ctx context.Context, tokenHash, passwordHash string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id string
	if err = tx.QueryRow(ctx, "UPDATE password_resets SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING account_id", tokenHash).Scan(&id); err != nil {
		return err
	}
	if err = d.revokePasswordSessions(ctx, tx, id, passwordHash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(action,subject_id) VALUES('password.reset',$1)", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) ChangePassword(ctx context.Context, id, passwordHash string, verify func(string) (bool, error)) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentHash string
	if err = tx.QueryRow(ctx, "SELECT password_hash FROM accounts WHERE id=$1 AND status<>'disabled' FOR UPDATE", id).Scan(&currentHash); err != nil {
		return err
	}
	ok, err := verify(currentHash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidPassword
	}
	if err = d.revokePasswordSessions(ctx, tx, id, passwordHash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,action,subject_id) VALUES($1,'password.changed',$1)", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type ProfileUpdate struct{ Login, GivenName, FamilyName, Name, Avatar string }

func (d *DB) UpdateProfile(ctx context.Context, id string, p ProfileUpdate) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var email string
	if err = tx.QueryRow(ctx, "UPDATE accounts SET login=$1,given_name=$2,family_name=$3,name=$4,avatar_url=$5,updated_at=now() WHERE id=$6 AND status='active' RETURNING email", p.Login, p.GivenName, p.FamilyName, p.Name, p.Avatar, id).Scan(&email); err != nil {
		return err
	}
	payload := map[string]any{"user_id": id, "email": email, "login": p.Login, "name": p.Name, "given_name": p.GivenName, "family_name": p.FamilyName, "avatar_url": p.Avatar}
	projects, err := d.ProfileProjects(ctx, tx, id, "")
	if err != nil {
		return err
	}
	for _, project := range projects {
		if err = d.QueueEvent(ctx, tx, project, "profile.updated", id, payload); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,action,subject_id) VALUES($1,'profile.updated',$1)", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

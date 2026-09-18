package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func (d *DB) UpdateLegacyProfile(ctx context.Context, actor, client, project, id, name, avatar string) (map[string]any, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var email string
	if err = tx.QueryRow(ctx, "UPDATE accounts SET name=$1,given_name=$1,family_name='',avatar_url=$2,updated_at=now() WHERE id=$3 RETURNING email", name, avatar, id).Scan(&email); err != nil {
		return nil, err
	}
	var login string
	if err = tx.QueryRow(ctx, "SELECT login FROM accounts WHERE id=$1", id).Scan(&login); err != nil {
		return nil, err
	}
	payload := map[string]any{"user_id": id, "email": email, "login": login, "name": name, "given_name": name, "family_name": "", "avatar_url": avatar}
	if err = d.AuditEvent(ctx, tx, actor, client, project, "profile.updated", id, payload); err != nil {
		return nil, err
	}
	projects, err := d.ProfileProjects(ctx, tx, id, project)
	if err != nil {
		return nil, err
	}
	for _, other := range projects {
		if err = d.QueueEvent(ctx, tx, other, "profile.updated", id, payload); err != nil {
			return nil, err
		}
	}
	return payload, tx.Commit(ctx)
}

type AccessRequest struct{ ID, UserID, Email, Name string }

func (d *DB) PendingRequests(ctx context.Context, project string) ([]AccessRequest, error) {
	rows, err := d.Pool.Query(ctx, "SELECT q.id,q.account_id,a.email,a.name FROM access_requests q JOIN accounts a ON a.id=q.account_id WHERE q.project_id=$1 AND q.status='pending' ORDER BY q.created_at", project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AccessRequest{}
	for rows.Next() {
		var x AccessRequest
		if err = rows.Scan(&x.ID, &x.UserID, &x.Email, &x.Name); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	return items, rows.Err()
}

func (d *DB) ApproveRequest(ctx context.Context, actor, client, project, request string, roles []string) (map[string]any, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var id string
	if err = tx.QueryRow(ctx, "UPDATE access_requests SET status='approved',decided_at=now() WHERE id=$1 AND project_id=$2 AND status='pending' RETURNING account_id", request, project).Scan(&id); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,$3) ON CONFLICT(account_id,project_id) DO UPDATE SET roles=$3", id, project, roles); err != nil {
		return nil, err
	}
	payload, err := d.AccountPayload(ctx, tx, id, roles)
	if err != nil {
		return nil, err
	}
	if err = d.AuditEvent(ctx, tx, actor, client, project, "access.granted", id, payload); err != nil {
		return nil, err
	}
	return payload, tx.Commit(ctx)
}

func (d *DB) SetProjectRoles(ctx context.Context, actor, client, project, id string, roles []string) (map[string]any, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE project_access SET roles=$1 WHERE account_id=$2 AND project_id=$3", roles, id, project)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, pgx.ErrNoRows
	}
	payload, err := d.AccountPayload(ctx, tx, id, roles)
	if err != nil {
		return nil, err
	}
	if err = d.AuditEvent(ctx, tx, actor, client, project, "roles.changed", id, payload); err != nil {
		return nil, err
	}
	return payload, tx.Commit(ctx)
}

func (d *DB) RevokeProjectAccess(ctx context.Context, actor, client, project, id string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "DELETE FROM project_access WHERE account_id=$1 AND project_id=$2", id, project)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND project_id=$2 AND revoked_at IS NULL", id, project); err != nil {
		return err
	}
	if err = d.AuditEvent(ctx, tx, actor, client, project, "access.revoked", id, map[string]any{"user_id": id}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type AdminUser struct {
	ID, Email, Login, Name, Status string
	Verified, GlobalAdmin          bool
}
type AdminRequest struct{ ID, UserID, Project, Email, Name string }
type AdminAccess struct{ UserID, Project, Roles string }
type AdminView struct {
	Users    []AdminUser
	Requests []AdminRequest
	Access   []AdminAccess
	Projects []string
}

func (d *DB) AdminView(ctx context.Context) (AdminView, error) {
	v := AdminView{Users: []AdminUser{}, Requests: []AdminRequest{}, Access: []AdminAccess{}, Projects: []string{}}
	rows, err := d.Pool.Query(ctx, "SELECT id,email,login,name,status,email_verified_at IS NOT NULL,is_global_admin FROM accounts ORDER BY created_at DESC LIMIT 200")
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var x AdminUser
		if err = rows.Scan(&x.ID, &x.Email, &x.Login, &x.Name, &x.Status, &x.Verified, &x.GlobalAdmin); err != nil {
			break
		}
		v.Users = append(v.Users, x)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = d.Pool.Query(ctx, "SELECT q.id,q.account_id,q.project_id,a.email,a.name FROM access_requests q JOIN accounts a ON a.id=q.account_id WHERE q.status='pending' ORDER BY q.created_at LIMIT 200")
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var x AdminRequest
		if err = rows.Scan(&x.ID, &x.UserID, &x.Project, &x.Email, &x.Name); err != nil {
			break
		}
		v.Requests = append(v.Requests, x)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = d.Pool.Query(ctx, "SELECT p.account_id,p.project_id,array_to_string(p.roles,', ') FROM project_access p ORDER BY p.project_id,p.account_id LIMIT 300")
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var x AdminAccess
		if err = rows.Scan(&x.UserID, &x.Project, &x.Roles); err != nil {
			break
		}
		v.Access = append(v.Access, x)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = d.Pool.Query(ctx, "SELECT id FROM projects ORDER BY id")
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var project string
		if err = rows.Scan(&project); err != nil {
			break
		}
		v.Projects = append(v.Projects, project)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return v, err
}

func (d *DB) ActivateAccount(ctx context.Context, actor, id string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE accounts SET status='active',updated_at=now() WHERE id=$1 AND email_verified_at IS NOT NULL AND status IN ('pending','disabled')", id)
	if err != nil || tag.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,action,subject_id) VALUES($1,'account.activated',$2)", actor, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) DisableAccount(ctx context.Context, actor, id string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE accounts SET status='disabled',updated_at=now() WHERE id=$1 AND status<>'disabled' AND is_global_admin=false", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	for _, sql := range []string{
		"DELETE FROM browser_sessions WHERE account_id=$1",
		"UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND revoked_at IS NULL",
		"DELETE FROM authorization_codes WHERE account_id=$1",
		"DELETE FROM password_resets WHERE account_id=$1",
	} {
		if _, err = tx.Exec(ctx, sql, id); err != nil {
			return err
		}
	}
	projects, err := d.ProfileProjects(ctx, tx, id, "")
	if err != nil {
		return err
	}
	for _, project := range projects {
		if err = d.QueueEvent(ctx, tx, project, "access.revoked", id, map[string]any{"user_id": id}); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "DELETE FROM project_access WHERE account_id=$1", id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,action,subject_id) VALUES($1,'account.disabled',$2)", actor, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) GrantAccess(ctx context.Context, actor, user, project string, roles []string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, "SELECT status='active' AND email_verified_at IS NOT NULL FROM accounts WHERE id=$1", user).Scan(&active); err != nil {
		return err
	}
	if !active {
		return pgx.ErrNoRows
	}
	var old []string
	err = tx.QueryRow(ctx, "SELECT roles FROM project_access WHERE account_id=$1 AND project_id=$2 FOR UPDATE", user, project).Scan(&old)
	kind := "roles.changed"
	if errors.Is(err, pgx.ErrNoRows) {
		kind = "access.granted"
	} else if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,$3) ON CONFLICT(account_id,project_id) DO UPDATE SET roles=$3", user, project, roles); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE access_requests SET status='approved',decided_at=now() WHERE account_id=$1 AND project_id=$2 AND status='pending'", user, project); err != nil {
		return err
	}
	payload, err := d.AccountPayload(ctx, tx, user, roles)
	if err != nil {
		return err
	}
	if err = d.AuditEvent(ctx, tx, actor, "sso-admin", project, kind, user, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) RevokeAccess(ctx context.Context, actor, user, project string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "DELETE FROM project_access WHERE account_id=$1 AND project_id=$2", user, project)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND project_id=$2 AND revoked_at IS NULL", user, project); err != nil {
		return err
	}
	if err = d.AuditEvent(ctx, tx, actor, "sso-admin", project, "access.revoked", user, map[string]any{"user_id": user}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

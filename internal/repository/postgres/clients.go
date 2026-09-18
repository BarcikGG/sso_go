package postgres

import (
	"context"
	"strings"
)

func (d *DB) EnsureBootstrap(ctx context.Context, project, clientID, secretHash, redirect, adminID, adminEmail, adminHash string) error {
	if _, err := d.Pool.Exec(ctx, "INSERT INTO projects(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING", project); err != nil {
		return err
	}
	if clientID != "" && secretHash != "" && redirect != "" {
		if _, err := d.Pool.Exec(ctx, "INSERT INTO oidc_clients(id,project_id,secret_hash,redirect_uris) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", clientID, project, secretHash, []string{redirect}); err != nil {
			return err
		}
	}
	if adminEmail == "" || adminHash == "" {
		return nil
	}
	if _, err := d.Pool.Exec(ctx, "INSERT INTO accounts(id,email,login,password_hash,name,email_verified_at,status,is_global_admin) VALUES($1,$2,$2,$3,'Administrator',now(),'active',true) ON CONFLICT(email) DO UPDATE SET is_global_admin=true,status='active',email_verified_at=coalesce(accounts.email_verified_at,now())", adminID, adminEmail, adminHash); err != nil {
		return err
	}
	_, err := d.Pool.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) SELECT id,$1,ARRAY['admin'] FROM accounts WHERE email=$2 ON CONFLICT DO NOTHING", project, adminEmail)
	return err
}

func (d *DB) RegisterClient(ctx context.Context, id, project, hash string, redirects []string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO projects(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING", project); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO oidc_clients(id,project_id,secret_hash,redirect_uris) VALUES($1,$2,$3,$4)", id, project, hash, redirects); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) GrantProjectAdmin(ctx context.Context, project, email string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var user string
	if err = tx.QueryRow(ctx, "SELECT id FROM accounts WHERE email=$1 AND email_verified_at IS NOT NULL AND status='active'", strings.ToLower(strings.TrimSpace(email))).Scan(&user); err != nil {
		return err
	}
	var roles []string
	if err = tx.QueryRow(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,ARRAY['admin']::text[]) ON CONFLICT(account_id,project_id) DO UPDATE SET roles=CASE WHEN 'admin'=ANY(project_access.roles) THEN project_access.roles ELSE array_append(project_access.roles,'admin') END RETURNING roles", user, project).Scan(&roles); err != nil {
		return err
	}
	payload, err := d.AccountPayload(ctx, tx, user, roles)
	if err != nil {
		return err
	}
	if err = d.AuditEvent(ctx, tx, "operator", "sso-cli", project, "access.granted", user, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *DB) GrantGlobalAdmin(ctx context.Context, email string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id string
	if err = tx.QueryRow(ctx, "UPDATE accounts SET is_global_admin=true,updated_at=now() WHERE email=$1 AND status='active' AND email_verified_at IS NOT NULL RETURNING id", email).Scan(&id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(service_id,action,subject_id) VALUES('sso-cli','global_admin.granted',$1)", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

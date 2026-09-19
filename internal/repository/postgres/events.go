package postgres

import (
	"context"
	"encoding/json"

	"github.com/endl/sso_go/internal/security"

	"github.com/jackc/pgx/v5"
)

// QueueEvent writes both delivery channels in the caller's transaction.
// The advisory lock serializes sync cursors by commit order.
func (d *DB) QueueEvent(ctx context.Context, tx pgx.Tx, project, kind, account string, payload map[string]any) error {
	if kind == "profile.updated" {
		var roles []string
		if err := tx.QueryRow(ctx, "SELECT roles FROM project_access WHERE account_id=$1 AND project_id=$2", account, project).Scan(&roles); err != nil {
			return err
		}
		copyPayload := make(map[string]any, len(payload)+1)
		for key, value := range payload {
			copyPayload[key] = value
		}
		copyPayload["roles"] = roles
		payload = copyPayload
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO outbox(id,project_id,event_type,payload) VALUES($1,$2,$3,$4)", security.RandomToken(), project, kind, body); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(77213003)"); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO sync_events(project_id,event_type,account_id,payload) VALUES($1,$2,$3,$4)", project, kind, account, body)
	return err
}

func (d *DB) AuditEvent(ctx context.Context, tx pgx.Tx, actor, client, project, kind, account string, payload map[string]any) error {
	if _, err := tx.Exec(ctx, "INSERT INTO audit_events(actor_id,service_id,project_id,action,subject_id) VALUES($1,$2,$3,$4,$5)", actor, client, project, kind, account); err != nil {
		return err
	}
	return d.QueueEvent(ctx, tx, project, kind, account, payload)
}

func (d *DB) ProfileProjects(ctx context.Context, tx pgx.Tx, account, origin string) ([]string, error) {
	rows, err := tx.Query(ctx, "SELECT project_id FROM project_access WHERE account_id=$1 AND project_id<>$2 ORDER BY project_id", account, origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := []string{}
	for rows.Next() {
		var project string
		if err = rows.Scan(&project); err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func (d *DB) AccountPayload(ctx context.Context, tx pgx.Tx, user string, roles []string) (map[string]any, error) {
	var email, login, name, given, family, avatar string
	var oldID *int64
	err := tx.QueryRow(ctx, "SELECT email,login,name,given_name,family_name,avatar_url,old_id FROM accounts WHERE id=$1 AND status='active' AND email_verified_at IS NOT NULL", user).Scan(&email, &login, &name, &given, &family, &avatar, &oldID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"user_id": user, "old_id": oldID, "email": email, "login": login, "name": name, "given_name": given, "family_name": family, "avatar_url": avatar, "roles": roles}, nil
}

type SyncEvent struct {
	ID      int64          `json:"id"`
	Type    string         `json:"type"`
	UserID  string         `json:"user_id"`
	Payload map[string]any `json:"payload"`
}

type Snapshot struct {
	ProjectID     string           `json:"project_id"`
	Cursor        int64            `json:"cursor"`
	Users         []map[string]any `json:"users"`
	NextAfterUser string           `json:"next_after_user"`
}

func (d *DB) Snapshot(ctx context.Context, project, after string, requestedCursor *int64) (Snapshot, error) {
	result := Snapshot{ProjectID: project, Users: []map[string]any{}}
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if requestedCursor != nil {
		result.Cursor = *requestedCursor
	} else if err = tx.QueryRow(ctx, "SELECT coalesce(max(id),0) FROM sync_events").Scan(&result.Cursor); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT a.id,a.old_id,a.email,a.login,a.name,a.given_name,a.family_name,a.avatar_url,p.roles
		FROM project_access p JOIN accounts a ON a.id=p.account_id
		WHERE p.project_id=$1 AND a.id>$2 AND a.status='active' AND a.email_verified_at IS NOT NULL
		ORDER BY a.id LIMIT 201`, project, after)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var id, email, login, name, given, family, avatar string
		var oldID *int64
		var roles []string
		if err = rows.Scan(&id, &oldID, &email, &login, &name, &given, &family, &avatar, &roles); err != nil {
			break
		}
		result.Users = append(result.Users, map[string]any{"user_id": id, "old_id": oldID, "email": email, "login": login, "name": name, "given_name": given, "family_name": family, "avatar_url": avatar, "roles": roles})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	if len(result.Users) > 200 {
		result.Users = result.Users[:200]
		result.NextAfterUser = result.Users[199]["user_id"].(string)
	}
	return result, nil
}

func (d *DB) Changes(ctx context.Context, project string, after int64) ([]SyncEvent, int64, error) {
	rows, err := d.Pool.Query(ctx, "SELECT id,event_type,account_id,payload FROM sync_events WHERE project_id=$1 AND id>$2 ORDER BY id LIMIT 200", project, after)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	events := []SyncEvent{}
	for rows.Next() {
		var event SyncEvent
		var raw []byte
		if err = rows.Scan(&event.ID, &event.Type, &event.UserID, &raw); err != nil {
			return nil, after, err
		}
		if err = json.Unmarshal(raw, &event.Payload); err != nil {
			return nil, after, err
		}
		events = append(events, event)
		after = event.ID
	}
	return events, after, rows.Err()
}

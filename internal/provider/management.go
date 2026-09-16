package provider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"strings"

	"github.com/endl/sso_go/internal/store/postgres"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *Server) actor(ctx context.Context, project string, admin bool) (string, postgres.Client, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	id := first(md.Get("x-client-id"))
	secret := first(md.Get("x-client-secret"))
	raw := strings.TrimPrefix(first(md.Get("authorization")), "Bearer ")
	c, err := s.DB.Client(ctx, id)
	if err != nil || c.Project != project || subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(postgres.Hash(secret))) != 1 {
		return "", postgres.Client{}, status.Error(codes.Unauthenticated, "invalid service credentials")
	}
	claims, err := s.keys.Verify(ctx, raw, s.issuer+"/grpc", "at+jwt")
	if err != nil || claims["client_id"] != id || claims["project_id"] != project {
		return "", postgres.Client{}, status.Error(codes.Unauthenticated, "invalid user token")
	}
	user, _ := claims["sub"].(string)
	if user == "" {
		return "", postgres.Client{}, status.Error(codes.Unauthenticated, "invalid subject")
	}
	roles, err := s.DB.Access(ctx, user, project)
	if err != nil {
		return "", postgres.Client{}, status.Error(codes.PermissionDenied, "project access required")
	}
	if admin {
		if !contains(roles, "admin") {
			return "", postgres.Client{}, status.Error(codes.PermissionDenied, "project administrator required")
		}
	}
	return user, c, nil
}
func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
func contains(v []string, x string) bool {
	for _, a := range v {
		if a == x {
			return true
		}
	}
	return false
}
func (s *Server) getUser(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	actor, _, err := s.actor(ctx, project, false)
	if err != nil {
		return nil, err
	}
	id := field(v, "user_id")
	if id == "" {
		id = actor
	}
	if id != actor {
		roles, _ := s.DB.Access(ctx, actor, project)
		if !contains(roles, "admin") {
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}
	}
	a, err := s.DB.Account(ctx, id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	roles, _ := s.DB.Access(ctx, id, project)
	return response(map[string]any{"user_id": a.ID, "email": a.Email, "name": a.Name, "avatar_url": a.Avatar, "roles": roles})
}
func (s *Server) updateProfile(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	actor, c, err := s.actor(ctx, project, false)
	if err != nil {
		return nil, err
	}
	id := field(v, "user_id")
	if id == "" {
		id = actor
	}
	if id != actor {
		return nil, status.Error(codes.PermissionDenied, "can only change own profile")
	}
	name := strings.TrimSpace(field(v, "name"))
	avatar := strings.TrimSpace(field(v, "avatar_url"))
	if name == "" || len(name) > 200 || len(avatar) > 2048 {
		return nil, status.Error(codes.InvalidArgument, "invalid profile")
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var email string
	err = tx.QueryRow(ctx, "UPDATE accounts SET name=$1,avatar_url=$2,updated_at=now() WHERE id=$3 RETURNING email", name, avatar, id).Scan(&email)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"user_id": id, "email": email, "name": name, "avatar_url": avatar}
	if err = s.auditOutbox(ctx, tx, actor, c.ID, project, "profile.updated", id, payload); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response(payload)
}
func (s *Server) listRequests(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	if _, _, err := s.actor(ctx, project, true); err != nil {
		return nil, err
	}
	rows, err := s.DB.Pool.Query(ctx, "SELECT q.id,q.account_id,a.email,a.name FROM access_requests q JOIN accounts a ON a.id=q.account_id WHERE q.project_id=$1 AND q.status='pending' ORDER BY q.created_at", project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id, user, email, name string
		if err = rows.Scan(&id, &user, &email, &name); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"request_id": id, "user_id": user, "email": email, "name": name})
	}
	return response(map[string]any{"requests": items})
}
func (s *Server) approve(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	actor, c, err := s.actor(ctx, project, true)
	if err != nil {
		return nil, err
	}
	roles := stringsField(v, "roles")
	if len(roles) == 0 {
		roles = []string{"member"}
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, "UPDATE access_requests SET status='approved',decided_at=now() WHERE id=$1 AND project_id=$2 AND status='pending' RETURNING account_id", field(v, "request_id"), project).Scan(&id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "pending request not found")
	}
	if _, err = tx.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,$3) ON CONFLICT(account_id,project_id) DO UPDATE SET roles=$3", id, project, roles); err != nil {
		return nil, err
	}
	payload := map[string]any{"user_id": id, "roles": roles}
	if err = s.auditOutbox(ctx, tx, actor, c.ID, project, "access.granted", id, payload); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response(payload)
}
func (s *Server) setRoles(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	actor, c, err := s.actor(ctx, project, true)
	if err != nil {
		return nil, err
	}
	id := field(v, "user_id")
	roles := stringsField(v, "roles")
	if id == "" || len(roles) == 0 {
		return nil, status.Error(codes.InvalidArgument, "user and roles required")
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE project_access SET roles=$1 WHERE account_id=$2 AND project_id=$3", roles, id, project)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "access not found")
	}
	payload := map[string]any{"user_id": id, "roles": roles}
	if err = s.auditOutbox(ctx, tx, actor, c.ID, project, "roles.changed", id, payload); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response(payload)
}
func (s *Server) revoke(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	project := field(v, "project_id")
	actor, c, err := s.actor(ctx, project, true)
	if err != nil {
		return nil, err
	}
	id := field(v, "user_id")
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "DELETE FROM project_access WHERE account_id=$1 AND project_id=$2", id, project)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "access not found")
	}
	_, _ = tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at=now() WHERE account_id=$1 AND project_id=$2 AND revoked_at IS NULL", id, project)
	payload := map[string]any{"user_id": id}
	if err = s.auditOutbox(ctx, tx, actor, c.ID, project, "access.revoked", id, payload); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response(payload)
}
func (s *Server) auditOutbox(ctx context.Context, tx pgx.Tx, actor, client, project, kind, subject string, payload map[string]any) error {
	if _, err := tx.Exec(ctx, "INSERT INTO audit_events(actor_id,service_id,project_id,action,subject_id) VALUES($1,$2,$3,$4,$5)", actor, client, project, kind, subject); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO outbox(id,project_id,event_type,payload) VALUES($1,$2,$3,$4)", random(), project, kind, body)
	return err
}

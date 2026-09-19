package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const projectID = "main_api"

type legacyUser struct {
	OldID     int64
	Email     string
	Hash      string
	Name      string
	Status    string
	Role      string
	RoleID    *int64
	CreatedAt *time.Time
}

func main() {
	apply := flag.Bool("apply", false, "write accounts and project access; default is dry-run")
	flag.Parse()
	if err := run(context.Background(), *apply); err != nil {
		fmt.Fprintln(os.Stderr, "import failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, apply bool) error {
	legacyURL, ssoURL := os.Getenv("LEGACY_DATABASE_URL"), os.Getenv("SSO_DATABASE_URL")
	if legacyURL == "" || ssoURL == "" {
		return errors.New("LEGACY_DATABASE_URL and SSO_DATABASE_URL are required")
	}
	legacy, err := pgxpool.New(ctx, legacyURL)
	if err != nil {
		return err
	}
	defer legacy.Close()
	sso, err := pgxpool.New(ctx, ssoURL)
	if err != nil {
		return err
	}
	defer sso.Close()
	if err = legacy.Ping(ctx); err != nil {
		return fmt.Errorf("legacy database: %w", err)
	}
	if err = sso.Ping(ctx); err != nil {
		return fmt.Errorf("SSO database: %w", err)
	}
	users, err := readUsers(ctx, legacy)
	if err != nil {
		return err
	}
	var newCount, existingCount, conflicts, approved, disabled int
	for _, u := range users {
		if u.Status == "approved" {
			approved++
		} else {
			disabled++
		}
		var id string
		var oldID *int64
		err = sso.QueryRow(ctx, "SELECT id,old_id FROM accounts WHERE lower(email)=$1 OR old_id=$2", u.Email, u.OldID).Scan(&id, &oldID)
		if errors.Is(err, pgx.ErrNoRows) {
			newCount++
			continue
		}
		if err != nil {
			return err
		}
		if oldID == nil || *oldID != u.OldID {
			conflicts++
		} else {
			existingCount++
		}
	}
	fmt.Printf("legacy users=%d, new=%d, already imported=%d, conflicts=%d, approved=%d, inactive=%d\n", len(users), newCount, existingCount, conflicts, approved, disabled)
	if !apply {
		return nil
	}
	if conflicts != 0 {
		return errors.New("email or old_id conflicts require manual resolution before import")
	}
	var projectExists bool
	if err = sso.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)", projectID).Scan(&projectExists); err != nil || !projectExists {
		return errors.New("SSO project main_api is missing")
	}
	tx, err := sso.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	repo := &postgres.DB{Pool: sso}
	imported := 0
	for _, u := range users {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM accounts WHERE old_id=$1)", u.OldID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		id, idErr := security.NewUUIDv7()
		if idErr != nil {
			return idErr
		}
		status := "disabled"
		var verified *time.Time
		if u.Status == "approved" {
			status = "active"
			now := time.Now()
			verified = &now
		} else if u.Status == "pending" {
			status = "pending"
		}
		_, err = tx.Exec(ctx, `INSERT INTO accounts(id,old_id,email,login,password_hash,name,status,email_verified_at,created_at)
			VALUES($1,$2,$3,$3,$4,$5,$6,$7,coalesce($8,now()))`, id, u.OldID, u.Email, u.Hash, u.Name, status, verified, u.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert legacy account %d: %w", u.OldID, err)
		}
		if status == "active" {
			roles := []string{u.Role}
			if u.RoleID != nil {
				roles = append(roles, fmt.Sprintf("legacy-role-%d", *u.RoleID))
			}
			if _, err = tx.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,$3)", id, projectID, roles); err != nil {
				return err
			}
			payload, payloadErr := repo.AccountPayload(ctx, tx, id, roles)
			if payloadErr != nil {
				return payloadErr
			}
			if err = repo.AuditEvent(ctx, tx, "", "legacy-import", projectID, "access.granted", id, payload); err != nil {
				return err
			}
		}
		imported++
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("imported=%d; project access and sync events written for active accounts\n", imported)
	return nil
}

func readUsers(ctx context.Context, db *pgxpool.Pool) ([]legacyUser, error) {
	rows, err := db.Query(ctx, `SELECT id,email,password,full_name,status,role,role_id,created_at AT TIME ZONE 'Europe/Moscow'
		FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []legacyUser{}
	seen := make(map[string]bool)
	for rows.Next() {
		var u legacyUser
		if err = rows.Scan(&u.OldID, &u.Email, &u.Hash, &u.Name, &u.Status, &u.Role, &u.RoleID, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Email = strings.ToLower(strings.TrimSpace(u.Email))
		parsed, parseErr := mail.ParseAddress(u.Email)
		if parseErr != nil || parsed.Address != u.Email || seen[u.Email] || !security.IsValidLegacyBcrypt(u.Hash) || u.Name == "" || (u.Status != "approved" && u.Status != "pending" && u.Status != "rejected") || (u.Role != "admin" && u.Role != "employee" && u.Role != "client") {
			return nil, fmt.Errorf("invalid legacy user record %d", u.OldID)
		}
		seen[u.Email] = true
		users = append(users, u)
	}
	return users, rows.Err()
}

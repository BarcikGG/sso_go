package provider

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/endl/sso_go/internal/store/postgres"
)

func page(w http.ResponseWriter, title, body string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><html><meta charset=utf-8><title>", template.HTMLEscapeString(title), "</title><body style='font:16px system-ui;max-width:38rem;margin:5rem auto'>")
	t := template.Must(template.New("body").Parse(body))
	_ = t.Execute(w, data)
	fmt.Fprint(w, "</body></html>")
}
func formCSRF(w http.ResponseWriter) string {
	token := random()
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso-form", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	return token
}
func validCSRF(r *http.Request) bool {
	c, err := r.Cookie("__Host-sso-form")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("csrf"))) == 1
}
func (s *Server) registerPage(w http.ResponseWriter, r *http.Request) {
	page(w, "Register", `<h1>Create account</h1><form method=post><input type=hidden name=csrf value="{{.}}"><label>Email <input name=email type=email required></label><br><label>Name <input name=name required></label><br><label>Password <input name=password type=password minlength=12 required></label><br><button>Create account</button></form><a href=/login>Sign in</a>`, formCSRF(w))
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "invalid form")
		return
	}
	if !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	pwd := r.FormValue("password")
	if !strings.Contains(email, "@") || name == "" || len(pwd) < 12 {
		problem(w, 400, "invalid registration")
		return
	}
	hashed, err := s.passwords.Hash(pwd)
	if err != nil {
		problem(w, 500, "registration failed")
		return
	}
	id, tok := random(), random()
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "registration failed")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "INSERT INTO accounts(id,email,password_hash,name) VALUES($1,$2,$3,$4)", id, email, hashed, name); err != nil {
		problem(w, 409, "email already registered")
		return
	}
	if _, err = tx.Exec(r.Context(), "INSERT INTO email_verifications(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", postgres.Hash(tok), id); err != nil {
		problem(w, 500, "registration failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "registration failed")
		return
	}
	link := s.issuer + "/verify?token=" + url.QueryEscape(tok)
	if err = s.sendVerification(email, link); err != nil {
		log.Printf("send verification email: %v", err)
		problem(w, 502, "verification email unavailable")
		return
	}
	page(w, "Check email", `<h1>Check your email</h1><p>Open the confirmation link, then sign in. If delivery fails, <a href=/verify/resend>request a new link</a>.</p>`, nil)
}
func (s *Server) resendPage(w http.ResponseWriter, r *http.Request) {
	page(w, "Resend confirmation", `<h1>Resend confirmation</h1><form method=post><input type=hidden name=csrf value="{{.}}"><input type=email name=email required><button>Send link</button></form>`, formCSRF(w))
}
func (s *Server) resend(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	var id string
	err := s.DB.Pool.QueryRow(r.Context(), "SELECT id FROM accounts WHERE email=$1 AND email_verified_at IS NULL", email).Scan(&id)
	if err == nil {
		tok := random()
		_, err = s.DB.Pool.Exec(r.Context(), "INSERT INTO email_verifications(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", postgres.Hash(tok), id)
		if err == nil {
			err = s.sendVerification(email, s.issuer+"/verify?token="+url.QueryEscape(tok))
		}
		if err != nil {
			log.Printf("resend verification: %v", err)
			problem(w, 502, "verification email unavailable")
			return
		}
	}
	page(w, "Check email", `<h1>Check your email</h1><p>If the account needs confirmation, a new link is on its way.</p>`, nil)
}
func (s *Server) sendVerification(email, link string) error {
	if s.smtpAddr == "" {
		return errors.New("SSO_SMTP_ADDR is required")
	}
	from := s.smtpFrom
	if from == "" {
		from = "sso@localhost"
	}
	mode := os.Getenv("SSO_SMTP_MODE")
	var c *smtp.Client
	var err error
	switch mode {
	case "plain":
		c, err = smtp.Dial(s.smtpAddr)
	case "tls":
		c, err = smtp.DialTLS(s.smtpAddr, nil)
	case "", "starttls":
		c, err = smtp.DialStartTLS(s.smtpAddr, nil)
	default:
		return errors.New("invalid SSO_SMTP_MODE")
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if username := os.Getenv("SSO_SMTP_USER"); username != "" {
		if err = c.Auth(sasl.NewPlainClient("", username, os.Getenv("SSO_SMTP_PASSWORD"))); err != nil {
			return err
		}
	}
	body := "From: " + from + "\r\nTo: " + email + "\r\nSubject: Confirm your email\r\n\r\n" + link + "\r\n"
	if err = c.SendMail(from, []string{email}, strings.NewReader(body)); err != nil {
		return err
	}
	return c.Quit()
}
func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		problem(w, 400, "invalid link")
		return
	}
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		problem(w, 500, "verification failed")
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	err = tx.QueryRow(r.Context(), "UPDATE email_verifications SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING account_id", postgres.Hash(tok)).Scan(&id)
	if err != nil {
		problem(w, 400, "link expired or used")
		return
	}
	if _, err = tx.Exec(r.Context(), "UPDATE accounts SET email_verified_at=now() WHERE id=$1", id); err != nil {
		problem(w, 500, "verification failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		problem(w, 500, "verification failed")
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	page(w, "Sign in", `<h1>Sign in</h1><form method=post action=/login><input type=hidden name=csrf value="{{.CSRF}}"><input type=hidden name=next value="{{.Next}}"><label>Email <input type=email name=email required></label><br><label>Password <input type=password name=password required></label><br><button>Sign in</button></form><a href=/register>Create account</a>`, struct{ CSRF, Next string }{formCSRF(w), next})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "invalid form")
		return
	}
	if !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	var id, pwd string
	var verified *time.Time
	err := s.DB.Pool.QueryRow(r.Context(), "SELECT id,password_hash,email_verified_at FROM accounts WHERE email=$1", strings.ToLower(strings.TrimSpace(r.FormValue("email")))).Scan(&id, &pwd, &verified)
	if err != nil {
		problem(w, 401, "invalid credentials")
		return
	}
	ok, err := s.passwords.Verify(r.FormValue("password"), pwd)
	if err != nil || !ok {
		problem(w, 401, "invalid credentials")
		return
	}
	if verified == nil {
		problem(w, 403, "email not verified")
		return
	}
	token := random()
	_, err = s.DB.Pool.Exec(r.Context(), "INSERT INTO browser_sessions(token_hash,account_id,expires_at) VALUES($1,$2,now()+interval '7 days')", postgres.Hash(token), id)
	if err != nil {
		problem(w, 500, "session unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 604800})
	next := safeNext(r.FormValue("next"))
	http.Redirect(w, r, next, http.StatusSeeOther)
}
func safeNext(next string) string {
	if next == "/projects" || strings.HasPrefix(next, "/authorize?") && !strings.ContainsAny(next, "\\\r\n") {
		return next
	}
	return "/projects"
}
func (s *Server) session(r *http.Request) (string, error) {
	c, err := r.Cookie("__Host-sso")
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.Pool.QueryRow(r.Context(), "SELECT account_id FROM browser_sessions WHERE token_hash=$1 AND expires_at>now()", postgres.Hash(c.Value)).Scan(&id)
	return id, err
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	if c, err := r.Cookie("__Host-sso"); err == nil {
		_, _ = s.DB.Pool.Exec(r.Context(), "DELETE FROM browser_sessions WHERE token_hash=$1", postgres.Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	user, err := s.session(r)
	if err != nil {
		http.Redirect(w, r, "/login?next=/projects", http.StatusSeeOther)
		return
	}
	rows, err := s.DB.Pool.Query(r.Context(), "SELECT p.id,p.name,CASE WHEN a.account_id IS NOT NULL THEN 'granted' ELSE coalesce(q.status,'none') END FROM projects p LEFT JOIN project_access a ON a.project_id=p.id AND a.account_id=$1 LEFT JOIN access_requests q ON q.project_id=p.id AND q.account_id=$1", user)
	if err != nil {
		problem(w, 500, "projects unavailable")
		return
	}
	defer rows.Close()
	var list []struct{ ID, Name, Status string }
	for rows.Next() {
		var x struct{ ID, Name, Status string }
		if rows.Scan(&x.ID, &x.Name, &x.Status) == nil {
			list = append(list, x)
		}
	}
	page(w, "Projects", `<h1>Projects</h1>{{range .Projects}}<p>{{.Name}} — {{.Status}} {{if eq .Status "none"}}<form method=post action=/access/request><input type=hidden name=csrf value="{{$.CSRF}}"><input type=hidden name=project value="{{.ID}}"><button>Request access</button></form>{{end}}</p>{{end}}<form method=post action=/logout><input type=hidden name=csrf value="{{.CSRF}}"><button>Sign out</button></form>`, struct {
		Projects []struct{ ID, Name, Status string }
		CSRF     string
	}{list, formCSRF(w)})
}
func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	user, err := s.session(r)
	if err != nil {
		problem(w, 401, "sign in required")
		return
	}
	a, err := s.DB.Account(r.Context(), user)
	if err != nil || a.Verified == nil {
		problem(w, 403, "email not verified")
		return
	}
	project := r.FormValue("project")
	_, err = s.DB.Pool.Exec(r.Context(), "INSERT INTO access_requests(id,account_id,project_id) VALUES($1,$2,$3) ON CONFLICT(account_id,project_id) DO NOTHING", random(), user, project)
	if err != nil {
		problem(w, 400, "unknown project")
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

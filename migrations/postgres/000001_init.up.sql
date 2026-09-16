CREATE TABLE accounts (
  id text PRIMARY KEY, email text NOT NULL UNIQUE, password_hash text NOT NULL,
  email_verified_at timestamptz, name text NOT NULL DEFAULT '', avatar_url text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE email_verifications (
  token_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id),
  expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE projects (id text PRIMARY KEY, name text NOT NULL);
CREATE TABLE oidc_clients (
  id text PRIMARY KEY, project_id text NOT NULL REFERENCES projects(id), secret_hash text NOT NULL,
  redirect_uris text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE project_access (
  account_id text NOT NULL REFERENCES accounts(id), project_id text NOT NULL REFERENCES projects(id),
  roles text[] NOT NULL DEFAULT '{}', granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(account_id, project_id)
);
CREATE TABLE access_requests (
  id text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id),
  project_id text NOT NULL REFERENCES projects(id), status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(), decided_at timestamptz,
  UNIQUE(account_id, project_id)
);
CREATE TABLE browser_sessions (
  token_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id),
  expires_at timestamptz NOT NULL
);
CREATE TABLE authorization_codes (
  code_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id), client_id text NOT NULL REFERENCES oidc_clients(id),
  redirect_uri text NOT NULL, nonce text NOT NULL, code_challenge text NOT NULL,
  scopes text[] NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE refresh_tokens (
  token_hash text PRIMARY KEY, family_id text NOT NULL, account_id text NOT NULL REFERENCES accounts(id),
  client_id text NOT NULL REFERENCES oidc_clients(id), project_id text NOT NULL REFERENCES projects(id),
  scopes text[] NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, revoked_at timestamptz
);
CREATE INDEX refresh_family_idx ON refresh_tokens(family_id);
CREATE TABLE signing_keys (
  kid text PRIMARY KEY, private_pem bytea NOT NULL, public_jwk jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), retired_at timestamptz, publish_until timestamptz
);
CREATE TABLE audit_events (
  id bigserial PRIMARY KEY, actor_id text, service_id text, project_id text,
  action text NOT NULL, subject_id text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE outbox (
  id text PRIMARY KEY, project_id text NOT NULL, event_type text NOT NULL, payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz,
  attempts integer NOT NULL DEFAULT 0, last_error text
);
CREATE INDEX outbox_pending_idx ON outbox(created_at) WHERE published_at IS NULL;

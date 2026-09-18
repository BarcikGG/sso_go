ALTER TABLE accounts ADD COLUMN login text;
UPDATE accounts SET login=email;
ALTER TABLE accounts ALTER COLUMN login SET NOT NULL;
CREATE UNIQUE INDEX accounts_login_lower_idx ON accounts(lower(login));
ALTER TABLE accounts ADD COLUMN given_name text NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN family_name text NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending','active','disabled'));
ALTER TABLE accounts ADD COLUMN is_global_admin boolean NOT NULL DEFAULT false;

CREATE TABLE password_resets (
  token_hash text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
CREATE INDEX password_resets_account_idx ON password_resets(account_id) WHERE used_at IS NULL;

CREATE TABLE auth_limits (
  key_hash text PRIMARY KEY,
  attempts integer NOT NULL,
  window_until timestamptz NOT NULL
);

ALTER TABLE refresh_tokens ADD COLUMN family_expires_at timestamptz;
UPDATE refresh_tokens SET family_expires_at=expires_at;
ALTER TABLE refresh_tokens ALTER COLUMN family_expires_at SET NOT NULL;

CREATE TABLE sync_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id),
  event_type text NOT NULL,
  account_id text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sync_events_project_id_idx ON sync_events(project_id,id);

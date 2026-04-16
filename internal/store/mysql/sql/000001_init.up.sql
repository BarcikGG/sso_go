CREATE TABLE IF NOT EXISTS users (
    id CHAR(32) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(512) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    roles_json JSON NOT NULL,
    permissions_json JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(32) PRIMARY KEY,
    user_id CHAR(32) NOT NULL,
    family_id CHAR(32) NOT NULL,
    parent_session_id CHAR(32) NULL,
    replaced_by_session_id CHAR(32) NULL,
    refresh_token_hash CHAR(64) NOT NULL UNIQUE,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_family_id (family_id),
    INDEX idx_sessions_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id CHAR(32) PRIMARY KEY,
    user_id CHAR(32) NULL,
    event_type VARCHAR(128) NOT NULL,
    metadata_json JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    INDEX idx_audit_events_user_id (user_id),
    INDEX idx_audit_events_event_type (event_type),
    INDEX idx_audit_events_created_at (created_at),
    CONSTRAINT fk_audit_events_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id CHAR(32) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL UNIQUE,
    secret_hash VARCHAR(512) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    scopes_json JSON NOT NULL,
    roles_json JSON NOT NULL,
    permissions_json JSON NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
);

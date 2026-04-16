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
    refresh_token_hash CHAR(64) NOT NULL UNIQUE,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_expires_at (expires_at)
);

# sso_go

Centralized SSO service for internal applications.

## Current status

Bootstrap iteration completed:

- project layout created
- config loading added
- HTTP server added
- health and readiness endpoints added
- working in-memory auth flow added
- initial SQL migration scaffold added
- password hashing and refresh token primitives added
- database config and migration scaffolding added
- access tokens are signed with `Ed25519`
- MySQL-backed storage is supported for persistent mode
- MySQL migrations can run automatically on startup
- auth audit events are recorded by the active store

## Run

```bash
go run ./cmd/sso
```

For local login bootstrap, set:

```bash
export SSO_BOOTSTRAP_ADMIN_EMAIL=admin@example.local
export SSO_BOOTSTRAP_ADMIN_USERNAME=admin
export SSO_BOOTSTRAP_ADMIN_PASSWORD=change-me
```

For MySQL mode, also set:

```bash
export SSO_DATABASE_DRIVER=mysql
export SSO_DATABASE_URL='user:password@tcp(127.0.0.1:3306)/sso?parseTime=true'
```

## Environment variables

- `SSO_APP_NAME`
- `SSO_ENV`
- `SSO_HTTP_PORT`
- `SSO_ISSUER`
- `SSO_ACCESS_TOKEN_TTL`
- `SSO_REFRESH_TOKEN_TTL`
- `SSO_SIGNING_KEY`
- `SSO_DATABASE_DRIVER`
- `SSO_DATABASE_URL`
- `SSO_DATABASE_AUTO_MIGRATE`
- `SSO_BOOTSTRAP_ADMIN_EMAIL`
- `SSO_BOOTSTRAP_ADMIN_USERNAME`
- `SSO_BOOTSTRAP_ADMIN_PASSWORD`

## Next step

Implement:

- request-scoped audit fields: IP, user agent, request id
- client-side auth SDK for FastAPI

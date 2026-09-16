# SSO provider

Подробное описание архитектуры, OIDC-потока и пошаговое подключение нового приложения: [документация на русском](docs/architecture-and-integration.ru.md).

The `cmd/sso` binary serves the OIDC Authorization Code flow and a protected gRPC management API. Fosite validates registered OAuth clients, scopes, response type, and redirect URIs at `/authorize`; PostgreSQL stores the authorization codes, PKCE challenges, sessions, hashed refresh tokens, project access, signing keys, audit records, and outbox events. The legacy JSON login API and MySQL store have been removed.

Run the complete local stack from the workspace root with `docker compose up --wait -d --build`. The shared login and registration pages are at `http://localhost:8080`, the pilot application at `http://localhost:8081`, and Mailpit at `http://localhost:8025`. The local bootstrap project and client are `main_api`; the bootstrap administrator is `admin@example.local` with password from `SSO_ADMIN_PASSWORD` (default `local-admin-password-change-me`). Set stronger values before sharing a local environment.

The PostgreSQL migration runner applies numbered migrations under `migrations/postgres` in a transaction. SSO needs `SSO_DATABASE_URL` and `SSO_ISSUER`. The Compose file shows the other settings: client registration, SMTP address and mode (`plain` only for local Mailpit, `starttls` by default, or `tls`), optional SMTP user/password, Kafka broker, and gRPC port. Set `SSO_GRPC_TLS_CERT` and `SSO_GRPC_TLS_KEY` for TLS gRPC. The client needs `SSO_GRPC_TLS_CA` to verify it. Public issuer and redirect URLs must match the browser-facing HTTPS addresses in deployment.

Register another project client with `SSO_NEW_CLIENT_SECRET=<secret> docker compose exec -T -e SSO_NEW_CLIENT_SECRET sso /sso --register-client CLIENT_ID PROJECT_ID https://app.example/callback`. Pass additional exact redirect URIs as further arguments. The command rejects wildcard, duplicate, and non-HTTPS remote URIs.

To bootstrap the first administrator of a new project after their email is verified, run `docker compose exec -T sso /sso --grant-project-admin PROJECT_ID admin@example.com`. This operator command records an audit entry and an outbox event.

Access tokens are five-minute RS256 JWTs for one project; management tokens use the SSO gRPC audience. Signing keys are persisted in PostgreSQL. Run `docker compose exec -T sso /sso --rotate-key` to rotate; the old public key remains in JWKS for ten minutes. Refresh tokens are SHA-256 hashed in SSO and rotated under a row lock. Reuse revokes the whole family. Service-specific roles are read from PostgreSQL when issuing tokens, and gRPC administrator rights are checked against current access.

The outbox publisher sends `sso.events` to Kafka and retains unsent rows. Consumers record event IDs and commit Kafka positions after their database transaction. `/metrics` exposes pending outbox rows, retried rows, and oldest pending age. The Compose setup is for local development; production needs durable PostgreSQL and Kafka, TLS, managed secrets, monitoring, and backups.

The pilot application's `/metrics` exposes Kafka errors, consumed events, `sync_pending` responses, and periodic copy mismatches for users with active sessions. Reconciliation runs outside ordinary requests.

Tests: `go test ./...` here; `go test ./...` in `main_api`; `python3 scripts/smoke.py` and `python3 scripts/recovery.py` from the workspace root after Compose starts. CI also runs the Playwright browser journey.

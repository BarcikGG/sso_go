# SSO Service Implementation Plan

## Goal

Build a standalone Go-based SSO service that provides centralized authentication and authorization for multiple internal applications. The service must work with current FastAPI projects and remain suitable for future Go services.

## Scope

### In Scope for MVP

- Central user authentication
- JWT access tokens
- Refresh tokens with rotation
- Logout and session revocation
- Role and permission model
- Public key distribution for token verification
- Integration model for FastAPI services
- Audit logging baseline

### Out of Scope for MVP

- SAML
- LDAP/Active Directory
- Social login
- MFA
- Full admin UI
- External identity federation

## Target Architecture

- Dedicated Go service acting as the central identity provider
- PostgreSQL as the main persistence layer
- Short-lived signed JWT access tokens
- Opaque refresh tokens stored hashed in the database
- Client services validate JWT locally using public keys exposed by SSO
- Browser applications authenticate through SSO and receive session/token state through a controlled flow

## Authentication Model

### Access Token

- Format: JWT
- Signature: `RS256` or `Ed25519`
- TTL: 5 to 15 minutes
- Primary claims:
  - `iss`
  - `sub`
  - `aud`
  - `exp`
  - `iat`
  - `nbf`
  - `jti`
  - `sid`
  - `roles`
  - `permissions`

### Refresh Token

- Format: opaque random token
- Stored in the database only in hashed form
- TTL: 7 to 30 days
- Rotated on every refresh
- Reuse detection revokes the session family

## Authorization Model

- Central RBAC in the SSO service
- Base entities:
  - users
  - roles
  - permissions
  - user_roles
  - role_permissions
- Client applications may enforce additional local authorization rules if needed

## Core Domain Entities

- `users`
- `password_credentials`
- `roles`
- `permissions`
- `role_permissions`
- `user_roles`
- `clients`
- `sessions`
- `refresh_tokens`
- `login_attempts`
- `audit_events`
- `signing_keys`

## API Surface

### Public/Auth

- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/logout-all`
- `GET /auth/me`
- `GET /.well-known/jwks.json`

### Admin

- `POST /users`
- `GET /users/{id}`
- `PATCH /users/{id}`
- `POST /users/{id}/roles`
- `DELETE /users/{id}/roles/{role}`
- `GET /sessions`
- `DELETE /sessions/{id}`

## Security Requirements

- Password hashing with `argon2id`
- Signed JWTs with key rotation support
- Strict validation of `iss`, `aud`, `exp`, and `nbf`
- Rate limiting on login endpoints
- Audit logging for successful and failed authentication events
- Session revocation on password change or user disable
- Secure cookie settings for browser-facing flows
- Secrets provided through environment variables or a secret manager

## FastAPI Integration Strategy

Build a reusable Python package for all FastAPI services with:

- JWKS fetching and caching
- JWT validation
- FastAPI dependency for current user extraction
- Role and permission guards

This removes duplicated authentication logic across projects.

## Recommended Go Stack

- HTTP router: `chi`
- Database: PostgreSQL
- DB driver: `pgx`
- Migrations: `golang-migrate`
- Config: environment-based typed config
- Logging: `zap`
- Metrics: Prometheus
- Tracing: OpenTelemetry

## Implementation Phases

### Phase 1. Discovery and Decisions

- List all client applications
- Define user journeys: login, logout, refresh, revoke
- Define audiences and claims contract
- Decide browser integration model

Deliverable:
- architecture RFC

### Phase 2. Security Design

- Select signing algorithm
- Define TTLs
- Define refresh token rotation and revocation rules
- Define audit and rate-limit policy

Deliverable:
- security specification

### Phase 3. Data Model

- Design PostgreSQL schema
- Create initial migrations
- Define indexes and uniqueness rules

Deliverable:
- database schema and migrations

### Phase 4. Core Auth Service

- Login
- Access token issuance
- Refresh token issuance and rotation
- Logout and logout-all
- JWKS endpoint
- Current user endpoint

Deliverable:
- working auth API

### Phase 5. Admin Capabilities

- User management
- Role assignment
- Session listing and revocation

Deliverable:
- minimal admin API

### Phase 6. Client Integration

- Shared FastAPI auth package
- Pilot integration into one application
- Rollout to the remaining applications

Deliverable:
- first production-integrated client

### Phase 7. Hardening

- Metrics
- Alerts
- Key rotation
- Load tests
- Security review

Deliverable:
- production-ready baseline

## Rollout Strategy

1. Deploy the SSO service separately.
2. Integrate one non-critical FastAPI service first.
3. Run temporary dual-mode authentication if necessary.
4. Migrate remaining services in batches.
5. Remove duplicated local authentication logic from clients.

## Immediate Delivery Plan

### Iteration 1

- Bootstrap Go service
- Add typed config
- Add health endpoint
- Add auth route skeleton
- Add PostgreSQL migration structure
- Add JWT key management abstraction

### Iteration 2

- Implement user storage
- Implement password hashing and login
- Implement token issuance
- Implement refresh flow
- Implement logout and session storage

### Iteration 3

- Implement RBAC
- Add admin endpoints
- Add audit events
- Add JWKS
- Add FastAPI integration package contract

## Current Implementation Decision

The first code iteration will establish:

- project layout
- application bootstrap
- HTTP server
- configuration
- health endpoint
- auth endpoint skeleton
- migration scaffolding

That gives a stable base for adding the actual authentication logic in the next steps.

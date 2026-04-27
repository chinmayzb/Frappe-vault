# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — 2026-04-27

### Added
- `Vault Credential Group` DocType — logical namespace with owner and member roster
- `Vault Credential Entry` DocType — encrypted credential storage (URL, username, AES-256 password, expiry)
- `Vault Credential Version` DocType — append-only history for tracked field changes; stores SHA-256 hash of rotated passwords
- `Vault Access Grant` DocType — per-user, per-credential, time-bound access tokens
- `Vault Access Log` DocType — immutable audit trail (on_trash raises ValidationError)
- Three-layer permission model: Role → Group membership → Access Grant
- `vault.api` whitelisted REST endpoints: `reveal_password`, `copy_username`, `copy_password`, `grant_access`, `revoke_access`
- Rate limiting on reveal endpoint
- Scheduled jobs: daily expiry checker, hourly grant sweeper, monthly log archival stub
- Role bootstrapping on `install-app`: Vault Admin, Vault Manager, Vault Member
- Frappe Desk workspace with 4 shortcuts
- `vault.permissions` module wiring `permission_query_conditions` and `has_permission` hooks
- 23 integration tests using `frappe.tests.IntegrationTestCase` with per-test DB rollback

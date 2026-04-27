# Vault — Credentials Manager for Frappe

> A first-class, encrypted credentials manager built natively on the Frappe Framework. Store, share, and audit portal credentials across your organisation — without ever leaving your Frappe desk.

[![Frappe](https://img.shields.io/badge/Frappe-v16-blue)](https://frappeframework.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

---

## Why Vault?

Most teams store shared passwords in spreadsheets, chat messages, or generic password managers that have no concept of an ERP user, a business role, or an audit requirement. **Vault** changes that by embedding credential management directly inside Frappe/ERPNext — using the same roles, users, and permission model your team already knows.

- Passwords never leave your server unencrypted
- Access is tied to Frappe users, not separate accounts
- Every reveal, edit, and grant is logged and immutable
- Works alongside ERPNext, HRMS, CRM, Helpdesk — no extra infrastructure

---

## Features

| Area | What it does |
|---|---|
| **Encrypted storage** | Passwords stored via Frappe's AES-256 `Password` fieldtype — never in plaintext |
| **Credential Groups** | Logical namespaces (e.g. "Finance Portals", "GST Portals") with a named owner |
| **Three-layer access** | Role (`Vault Member`) → Group membership → Per-credential Access Grant |
| **Time-bound grants** | Grants carry an optional `expires_on` date; a daily sweep revokes stale ones |
| **Version history** | Every save that changes portal name, URL, username, password, or notes cuts a new version. Old-password SHA-256 hashes are stored — never the plaintext |
| **Immutable audit log** | `Vault Access Log` rows cannot be deleted. Every reveal, copy, edit, grant, and revoke is recorded with user + timestamp |
| **Expiry alerts** | A daily scheduler flags credentials past their `expiry_date` and sets `status = Expired` |
| **REST API** | Whitelisted Frappe endpoints for reveal, copy-username, copy-password, grant, and revoke — rate-limited out of the box |
| **Workspace** | Dedicated Frappe workspace with shortcuts to all four DocTypes |

---

## Architecture Overview

```
Vault Credential Group          ← owns N credentials, has one owner user and N members
  └── Vault Credential Entry    ← one credential (URL, username, encrypted password, expiry)
        ├── Vault Credential Version   ← append-only history of every tracked field change
        ├── Vault Access Grant         ← per-user, per-credential, time-bound access token
        └── Vault Access Log           ← immutable audit trail (on_trash raises exception)
```

### Access decision tree

```
Request to reveal credential C by user U
  ↓
1. Does U have the "Vault Admin" role?  → allow
2. Is U the owner of C's group?         → allow
3. Is U a member of C's group           → allow
   AND does U have an active Access Grant for C?
4. → deny (HTTP 403)
```

---

## Quick Start

### Requirements

- Frappe Framework v15 or v16 (tested on v16.0.0-dev)
- Python 3.10+
- Bench CLI

### Install

```bash
# From your bench directory
bench get-app https://github.com/chinmayzb/vault --branch main
bench --site <your-site> install-app vault
```

### First steps

1. Open **Vault** workspace in Frappe Desk
2. Create a **Vault Credential Group** and assign an owner
3. Add **Vault Members** to the group
4. Create **Vault Credential Entry** records inside the group
5. Issue **Vault Access Grants** to allow members to reveal individual credentials

---

## API Reference

All endpoints require an authenticated Frappe session or API key.

### Reveal password

```http
POST /api/method/vault.api.reveal_password
Content-Type: application/json

{ "credential": "VLT-GST Portal-00001" }
```

Returns `{ "password": "<decrypted>" }` and writes a `View` audit log entry.

### Copy username / password

```http
POST /api/method/vault.api.copy_username
POST /api/method/vault.api.copy_password

{ "credential": "VLT-GST Portal-00001" }
```

### Grant / Revoke access

```http
POST /api/method/vault.api.grant_access
{ "credential": "VLT-...", "user": "alice@example.com", "expires_on": "2026-12-31" }

POST /api/method/vault.api.revoke_access
{ "credential": "VLT-...", "user": "alice@example.com" }
```

---

## Roles

| Role | Capabilities |
|---|---|
| `Vault Admin` | Full read/write on all groups, credentials, grants, and logs |
| `Vault Manager` | Create/manage groups and credentials; issue grants to members |
| `Vault Member` | Read credentials they hold an active grant for; cannot create or edit |

Roles are created automatically on `bench install-app vault`.

---

## Scheduled Jobs

| Schedule | Function | Purpose |
|---|---|---|
| Daily | `run_expiry_checker` | Set `status = Expired` on past-expiry credentials |
| Hourly | `sweep_expired_grants` | Deactivate Access Grants past `expires_on` |
| Monthly | `archive_old_logs` | (Stub) Placeholder for log archival / export |

---

## Development

### Running tests

```bash
cd /path/to/frappe-bench
bench --site <site> run-tests --app vault
```

All 23 integration tests use `frappe.tests.IntegrationTestCase` with per-test database rollback. No fixtures are committed to the test database.

### Project structure

```
vault/
├── vault/
│   ├── api.py              # Whitelisted REST endpoints
│   ├── audit.py            # log_access(), hash_password()
│   ├── hooks.py            # Frappe app hooks
│   ├── install.py          # Role bootstrapping on install
│   ├── permissions.py      # permission_query_conditions, has_permission, user_has_active_grant
│   ├── scheduled.py        # Scheduler callbacks
│   ├── tests/
│   │   ├── utils.py        # make_user / make_group / make_credential helpers
│   │   ├── test_api.py
│   │   └── test_scheduled.py
│   └── vault/doctype/
│       ├── vault_access_grant/
│       ├── vault_access_log/
│       ├── vault_credential_entry/
│       ├── vault_credential_group/
│       └── vault_credential_version/
├── pyproject.toml
└── requirements.txt
```

---

## Security Notes

- Passwords are stored using Frappe's built-in `Password` fieldtype which encrypts values in the `tabSiteSecurity` / `tabAuth` table using AES-256 (key derived from `site_config.json → encryption_key`).
- Version history stores only a SHA-256 hash of the **previous** password, never the new one and never plaintext. The hash is for rotation auditing only — it cannot be used to recover the password.
- Audit log rows have `on_trash` overridden to raise `frappe.ValidationError`, making them tamper-resistant from the application layer.
- The `reveal_password` endpoint is rate-limited via `frappe.rate_limiter.rate_limit`.

---

## Contributing

Pull requests are welcome. Please open an issue first for significant changes.

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes
4. Push and open a PR

---

## License

MIT — see [license.txt](license.txt)

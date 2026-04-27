# Vault — Credentials Manager

Enterprise-grade credentials manager for Frappe / ERPNext.

A centralised, encrypted store for portal credentials with role-based access,
team-level isolation, full audit trails, and a structured versioning model.

## Features

- AES-encrypted password storage (Frappe `Password` fieldtype)
- Three-layer access model: Role → Group → Per-credential Grant
- Time-bound access grants with automatic revocation
- Full version history (SHA-256 hash of old passwords, never plaintext)
- Immutable audit log of every reveal / edit / grant event
- Daily expiry alerts and scheduled grant sweepers
- Native integration: works alongside ERPNext, HR, FCRM, Helpdesk, etc.

## Compatibility

- Frappe Framework v15+ (tested on v16)
- Python 3.10+

## Install

```bash
bench get-app vault /path/to/vault
bench --site <site> install-app vault
```

## Roles

- **Vault Admin** — full control
- **Vault Manager** — manage groups & credentials, grant access
- **Vault Member** — view credentials only when explicitly granted

## License

MIT

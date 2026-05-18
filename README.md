# PASSWORDVAULT
A self-hosted group password vault for Active Directory / LDAP environments. Passwords and notes are AES-256-GCM encrypted at rest. Access is controlled per folder and item via an ACL system tied to LDAP group membership.

## Requirements

- Docker + Docker Compose
- An Active Directory / LDAP server reachable from the container
- A 64-hex-character `MASTER_KEY` — generate one with:
  ```
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```

## Quick Start

```powershell
cp .env.example .env   # fill in required values (see below)
docker compose up --build -d
docker compose logs -f
```

The app is available on the configured `HOST_PORT` (default `3000`). Put it behind a reverse proxy (nginx, Traefik) for HTTPS — see `TRUST_PROXY` below.

## Environment Variables

| Variable | Required | Notes |
|---|---|---|
| `SESSION_SECRET` | ✅ | 64 hex chars |
| `MASTER_KEY` | ✅ | 64 hex chars — **never change after data exists** |
| `LDAP_URL` | ✅ | `ldaps://dc.corp.com:636` |
| `LDAP_BIND_DN` | ✅ | Service account DN |
| `LDAP_BIND_CREDENTIALS` | ✅ | Service account password |
| `LDAP_SEARCH_BASE` | ✅ | `OU=Users,DC=corp,DC=com` |
| `LDAP_SEARCH_FILTER` | optional | Default: `(sAMAccountName={{username}})` |
| `LDAP_ALLOWED_GROUP` | optional | Restrict login to members of this group DN |
| `GLOBAL_ADMIN` | optional | Username or group DN — grants admin on everything |
| `EMERGENCY_PASSWORD` | optional | Non-LDAP fallback login (use any username) |
| `ROOT_FOLDER_NAME` | optional | Name of the root vault folder (default: `FFManching`) |
| `DB_PATH` | optional | Path to SQLite database (default: `./data/passwords.db`) |
| `HOST_PORT` | optional | Host port to bind (default: `3000`) |
| `TRUST_PROXY` | optional | Set `true` when behind nginx/Traefik (enables secure cookies) |

## First Login

1. Log in with your LDAP credentials.
2. By default all authenticated users have **write** access to the root folder (can create subfolders and items).
3. To get **admin** access (required to manage permissions on subfolders), set `GLOBAL_ADMIN` to your username or a group DN in `.env` and restart.

## Permissions

Access levels: `read` → `write` → `admin`. Items inherit from their parent folder; folders inherit up the tree. If a resource has explicit ACL entries but the current user isn't in any of them, access is denied regardless of parent permissions.

The wildcard subject `*` matches all authenticated users.

## Key Operational Notes

- **`MASTER_KEY` is permanent.** Changing it after any passwords have been stored makes all existing data unreadable. There is no built-in key rotation utility.
- **`--experimental-sqlite` is mandatory.** The app uses Node 22's built-in `node:sqlite` module. This flag is already set in `package.json` and the Dockerfile — don't remove it.
- **TLS verification is disabled** for the LDAP connection (`rejectUnauthorized: false`). This is fine for internal AD with self-signed certificates. Replace with a proper CA cert for high-security environments.
- **Behind a reverse proxy**, set `TRUST_PROXY=true` so session cookies are flagged `Secure`. Without this, sessions won't persist over HTTPS.

## Development

```powershell
npm install
npm run dev   # node --watch --experimental-sqlite src/server.js
```

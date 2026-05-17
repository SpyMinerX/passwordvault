# LDAP Password Manager — Session Handoff

## What This Is

A self-hosted group password manager built with Node.js 22 + Express, deployed via Docker. All authenticated LDAP/AD users share a password vault structured as a folder tree. Passwords and notes are AES-256-GCM encrypted at rest. Access is controlled by a per-folder/per-item ACL system tied to LDAP group membership.

---

## File Structure

```
passwordmanager/
├── Dockerfile
├── docker-compose.yml
├── .env.example              ← copy to .env, fill in secrets
├── .dockerignore
├── package.json
├── HANDOFF.md                ← this file
├── src/
│   ├── server.js             ← Express bootstrap, helmet CSP, routes, favicon
│   ├── config.js             ← env validation at startup, exports frozen config
│   ├── auth.js               ← Passport LDAP strategy, memberOf stored in session
│   ├── middleware.js         ← requireAuth, resolvePermission, checkPermission, GLOBAL_ADMIN
│   ├── crypto.js             ← AES-256-GCM encrypt/decrypt
│   ├── db.js                 ← node:sqlite schema, prepared statements, root folder seed
│   ├── ldap.js               ← ldapts group/user search (ESM via dynamic import)
│   ├── routes/
│   │   ├── auth.js           ← GET/POST /login, /logout, emergency password check
│   │   ├── folders.js        ← folder CRUD, tree, items list, permissions
│   │   └── items.js          ← item CRUD, reveal password/notes, permissions, check-password
│   └── views/
│       ├── login.ejs         ← dark/light themed login page
│       └── app.ejs           ← full SPA: tree nav + content panel + all modals
└── data/
    └── .gitkeep              ← Docker volume mount point for SQLite DB
```

---

## Key Decisions & How Things Work

### Database — `node:sqlite` (built-in)
- Uses Node 22's built-in `node:sqlite` (`DatabaseSync`) — **no native compilation**.
- Started with `--experimental-sqlite` flag (in `package.json` scripts and `Dockerfile CMD`).
- This was chosen because `better-sqlite3` failed to build via `node-gyp` on a Windows UNC path (`\\NAS\...`).
- **BigInt gotcha**: `node:sqlite` returns integer columns as BigInt. Never use `> 0` on a `COUNT(*)` result — use `.get()` returning `undefined` for empty instead.

### Encryption — `src/crypto.js`
- `MASTER_KEY`: 64 hex chars (32 bytes). Validated at startup. **Losing this key = losing all data.**
- Per-item: 12-byte random IV stored in `password_iv` / `notes_iv` columns (base64).
- Storage format: `encrypted_password` = base64(16-byte GCM auth tag + ciphertext).
- `decrypt()` throws on tampered data (auth tag mismatch) — never swallow this error.
- Empty/null plaintext → `{ ciphertext: null, iv: null }` — handled cleanly.
- Generate key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

### Auth — `src/auth.js` + `src/routes/auth.js`
- Passport LDAP strategy via `passport-ldapauth`. No passwords stored.
- Session user object: `{ dn, username, displayName, memberOf: ['CN=Finance,...'] }`
- `memberOf` is always normalized to an array (LDAP can return a single string).
- **Emergency login**: `EMERGENCY_PASSWORD` env var. Checked with `crypto.timingSafeEqual` before LDAP. Sets `user.isEmergency = true` which bypasses ALL ACL checks → always returns `'admin'`.
- Session: 8h max age, `httpOnly`, `sameSite: lax`. Requires HTTPS + `TRUST_PROXY=true` behind nginx/traefik.

### Permission System — `src/middleware.js`

**Resolution algorithm** (`resolvePermission`):
1. Emergency users → `'admin'` (bypasses everything)
2. GLOBAL_ADMIN match → `'admin'` (see below)
3. Fetch explicit ACL entries for this resource
4. If entries exist → find highest level matching user/groups, or `null` if no match
5. If no entries → inherit: item → parent folder → grandparent → ... → root folder → `null`

**Default is `null` (hidden)** — nothing is visible without an explicit ACL entry or inheritance from a parent that has one. The root folder is seeded with `subject='*', level='write'` so all LDAP users start with write access to the root.

**Level hierarchy**: `admin > write > read`. Stored in DB as text, compared via `LEVEL_RANK`.

**Wildcard `*`**: stored as `subject_type='group', subject='*'` — matches everyone.
> ⚠ The DB schema CHECK constraint allows `subject_type IN ('group','user','everyone')` but the actual data uses `'group'` for wildcards. The `'everyone'` enum value is unused — it exists in the constraint but not in any real rows.

### GLOBAL_ADMIN — `src/config.js` + `src/middleware.js`
- Set `GLOBAL_ADMIN=` to either a **plain username** (sAMAccountName) or a **full group DN**.
- Both are checked: username exact match OR memberOf contains the value (case-insensitive).
- This user/group bypasses all ACL checks and gets `'admin'` on everything.
- Without this set, nobody has `admin` on the root folder by default (only `write` from the `*` seed).

### Debug Console API (GLOBAL_ADMIN only)
A hidden `window.__debug` object is injected into `app.ejs` for managing root folders from the browser devtools console. It is not linked to any UI element. Only works if the logged-in user is `GLOBAL_ADMIN`.

```javascript
__debug.listRootFolders()           // show all root folders with IDs
__debug.deleteRootFolder('OldName') // or by UUID — starts 10s confirmation window
__debug.confirm()                   // must be called within 10s to execute
```

Backend endpoint: `DELETE /api/folders/debug/root/:id` — server-side GLOBAL_ADMIN check, logs the deletion to the server console.

### Root Folder Protection
- The root folder (`parent_id IS NULL`, e.g. "FFManching") cannot be renamed, deleted, or have its permissions changed.
- **Backend**: `guardRootFolder()` in `routes/folders.js` returns 403 if `folder.parent_id IS NULL`.
- **Frontend**: `depth === 0` in `renderNode` hides all admin action buttons on root-level tree nodes.
- The root folder is seeded idempotently in `db.js:seedRootFolder()` — safe to restart.

### LDAP Search — `src/ldap.js`
- Uses `ldapts` v8 (ESM-only) loaded via `await import('ldapts')` from CommonJS. The client class is cached after first load.
- `escapeLdap()` escapes `*`, `(`, `)`, `\`, and NUL — required to prevent LDAP injection.
- Searches groups: `(&(objectClass=group)(cn=*query*))` — max 40 results.
- Searches users: sAMAccountName, displayName, or mail — excludes computer accounts.

### Password Strength & Duplicate Check
- **Complexity**: client-side only, instant. Scores length + character variety. Shows ⛔/⚠/✓ with bar.
- **Duplicate check**: `POST /api/items/check-password` — decrypts ALL item passwords server-side and counts matches. Excludes the current item when editing (`excludeId` param). Returns count only, never which items match.
- Debounced 700ms after last keystroke.

---

## Environment Variables (`.env`)

| Variable | Required | Notes |
|---|---|---|
| `SESSION_SECRET` | ✅ | 64 hex chars |
| `MASTER_KEY` | ✅ | 64 hex chars — **never change after data exists** |
| `LDAP_URL` | ✅ | `ldaps://dc.corp.com:636` |
| `LDAP_BIND_DN` | ✅ | Service account DN |
| `LDAP_BIND_CREDENTIALS` | ✅ | Service account password |
| `LDAP_SEARCH_BASE` | ✅ | `OU=Users,DC=corp,DC=com` |
| `LDAP_SEARCH_FILTER` | optional | Default: `(sAMAccountName={{username}})` |
| `LDAP_ALLOWED_GROUP` | optional | Restrict login to members of this group |
| `GLOBAL_ADMIN` | optional | Username or group DN — admin everywhere |
| `EMERGENCY_PASSWORD` | optional | Non-LDAP fallback login |
| `ROOT_FOLDER_NAME` | optional | Default: `FFManching` |
| `DB_PATH` | optional | Default: `./data/passwords.db` |
| `HOST_PORT` | optional | Default: `3000` |
| `TRUST_PROXY` | optional | Set `true` behind nginx/traefik |

---

## Running Locally (Dev)

```powershell
cd "\\GALAXYRNAS\VinceDocuments\07.Programing\LDAP passwordmanager"
cp .env.example .env   # then fill in values
npm install
npm run dev            # node --watch --experimental-sqlite src/server.js
```

## Docker

```powershell
docker compose up --build -d
docker compose logs -f
```

Image is tagged `spyminer/passwordvault`.

---

## Things to Watch Out For

### 1. Nobody gets `admin` by default
The root folder seed gives everyone `write`. `admin` must be explicitly granted on subfolders/items, OR set `GLOBAL_ADMIN`. Until `GLOBAL_ADMIN` is configured, **no one will see the permissions lock icon** on subfolders or items unless they have an explicit `admin` ACL entry on that resource.

### 2. Duplicate `onPermTypeChange` definition in `app.ejs`
Around line 770 and again around line 896 there are two `onPermTypeChange()` function declarations. In JS, the second definition wins (both are hoisted, last one wins). The first one is dead code. Harmless, but confusing — can be cleaned up by deleting the first occurrence.

### 3. `--experimental-sqlite` is mandatory
Forgetting this flag causes `Error: No such built-in module: node:sqlite`. It's in `package.json` scripts and the Dockerfile CMD — don't remove it. Node will likely stabilize this API in a future LTS and the flag can be dropped then.

### 4. MASTER_KEY is forever
If `MASTER_KEY` changes, all existing encrypted data becomes unreadable. There is no key rotation utility implemented. To rotate: decrypt everything with the old key, re-encrypt with the new key in a single transaction, then update the env. This is documented but not built.

### 5. `ldapts` TLS verification is disabled
`tlsOptions: { rejectUnauthorized: false }` is set in both `src/ldap.js` and `src/auth.js`. Fine for internal AD with self-signed certs, but should be replaced with a proper CA cert in high-security environments.

### 6. Password duplicate check decrypts everything
`POST /api/items/check-password` decrypts every password in the DB on every call. This is fine for small vaults (< a few thousand items) but will be slow at scale. Consider a salted hash index if the vault grows large.

### 7. Permissions modal has two contexts
`openPerms()` sets `state.permResourceType` and `state.permResourceId`. If the user opens the permissions modal from the inline panel button in the content area and then saves an item, the modal state is shared. No bug currently, but be careful if adding more ways to open the permissions modal.

---

## What Could Be Needed Next

- **Key rotation utility** — script to re-encrypt all items with a new MASTER_KEY
- **Audit log** — track who revealed which password and when (`revealed_at`, `revealed_by` columns)
- **Search / filter** — search items across all visible folders (currently must browse folder by folder)
- **Item categories / tags** — group related items within a folder
- **Password history** — store previous encrypted passwords per item (N versions)
- **Mobile layout** — the two-panel layout breaks on narrow screens; needs a hamburger menu for the tree
- **Session activity timeout** — auto-logout after inactivity (currently fixed 8h cookie)
- **Folder permissions panel for root** — currently hidden; could show a read-only view explaining the `*` wildcard
- **Bulk import** — CSV/KeePass/Bitwarden import for migrating existing passwords
- **Copy username button** — the reveal modal only copies the password; username needs an extra click
- **LDAP group sync** — if a user is removed from a group in AD, their access is revoked automatically (already works — `memberOf` is re-read at each login)

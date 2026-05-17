'use strict';

const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const { DatabaseSync } = require('node:sqlite');

let db;

function initDb(dbPath, rootFolderName) {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  runMigrations();
  if (rootFolderName) seedRootFolder(rootFolderName);
  console.log(`Database initialized at ${dbPath}`);
  return db;
}

function seedRootFolder(name) {
  // Idempotent: ensure the named root folder exists
  let folder = db.prepare('SELECT id FROM folders WHERE parent_id IS NULL AND name = ?').get(name);
  if (!folder) {
    const id = randomUUID();
    db.prepare('INSERT INTO folders (id,name,parent_id,created_at,created_by) VALUES (?,?,?,?,?)')
      .run(id, name, null, new Date().toISOString(), 'system');
    folder = { id };
    console.log(`Created root folder: ${name}`);
  }

  // Idempotent: ensure the everyone-write permission exists (stored as group/*)
  const hasPerm = db.prepare(
    "SELECT id FROM permissions WHERE resource_type='folder' AND resource_id=? AND subject='*'"
  ).get(folder.id);
  if (!hasPerm) {
    db.prepare('INSERT OR IGNORE INTO permissions (id,resource_type,resource_id,subject_type,subject,level) VALUES (?,?,?,?,?,?)')
      .run(randomUUID(), 'folder', folder.id, 'group', '*', 'write');
    console.log(`Granted everyone write access to: ${name}`);
  }
}

function getDb() {
  if (!db) throw new Error('Database not initialized — call initDb() first');
  return db;
}

function runMigrations() {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS folders (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      parent_id  TEXT REFERENCES folders(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS items (
      id                 TEXT PRIMARY KEY,
      folder_id          TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
      name               TEXT NOT NULL,
      username           TEXT,
      encrypted_password TEXT,
      password_iv        TEXT,
      encrypted_notes    TEXT,
      notes_iv           TEXT,
      created_at         TEXT NOT NULL,
      created_by         TEXT NOT NULL,
      modified_at        TEXT NOT NULL,
      modified_by        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS permissions (
      id            TEXT PRIMARY KEY,
      resource_type TEXT NOT NULL CHECK(resource_type IN ('folder','item')),
      resource_id   TEXT NOT NULL,
      subject_type  TEXT NOT NULL CHECK(subject_type IN ('group','user','everyone')),
      subject       TEXT NOT NULL,
      level         TEXT NOT NULL CHECK(level IN ('read','write','admin')),
      UNIQUE(resource_type, resource_id, subject_type, subject)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id            TEXT PRIMARY KEY,
      timestamp     TEXT NOT NULL,
      actor         TEXT NOT NULL,
      ip            TEXT,
      action        TEXT NOT NULL,
      resource_type TEXT,
      resource_id   TEXT,
      resource_name TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
    CREATE INDEX IF NOT EXISTS idx_items_folder   ON items(folder_id);
    CREATE INDEX IF NOT EXISTS idx_perms_resource ON permissions(resource_type, resource_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
  `);

  // V2: extend permissions level to include 'hide' (explicit deny override)
  if (!db.prepare('SELECT version FROM schema_version WHERE version = 2').get()) {
    db.exec(`PRAGMA foreign_keys = OFF`);
    db.exec(`
      CREATE TABLE permissions_new (
        id            TEXT PRIMARY KEY,
        resource_type TEXT NOT NULL CHECK(resource_type IN ('folder','item')),
        resource_id   TEXT NOT NULL,
        subject_type  TEXT NOT NULL CHECK(subject_type IN ('group','user','everyone')),
        subject       TEXT NOT NULL,
        level         TEXT NOT NULL CHECK(level IN ('read','write','admin','hide')),
        UNIQUE(resource_type, resource_id, subject_type, subject)
      )
    `);
    db.exec(`INSERT OR IGNORE INTO permissions_new SELECT * FROM permissions`);
    db.exec(`DROP TABLE permissions`);
    db.exec(`ALTER TABLE permissions_new RENAME TO permissions`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_perms_resource ON permissions(resource_type, resource_id)`);
    db.exec(`PRAGMA foreign_keys = ON`);
    db.prepare('INSERT OR IGNORE INTO schema_version (version) VALUES (2)').run();
    console.log('Migration v2: permissions now support "hide" level');
  }
}

function stmts() {
  const d = getDb();
  return {
    // Folders
    getFolderById:   d.prepare('SELECT * FROM folders WHERE id = ?'),
    getRootFolders:  d.prepare('SELECT * FROM folders WHERE parent_id IS NULL ORDER BY name'),
    getChildFolders: d.prepare('SELECT * FROM folders WHERE parent_id = ? ORDER BY name'),
    insertFolder:    d.prepare('INSERT INTO folders (id,name,parent_id,created_at,created_by) VALUES (?,?,?,?,?)'),
    updateFolder:    d.prepare('UPDATE folders SET name = ? WHERE id = ?'),
    deleteFolder:    d.prepare('DELETE FROM folders WHERE id = ?'),

    // Items (list excludes secret columns)
    getItemById:     d.prepare('SELECT * FROM items WHERE id = ?'),
    getItemsByFolder: d.prepare(
      'SELECT id,folder_id,name,username,created_at,created_by,modified_at,modified_by FROM items WHERE folder_id = ? ORDER BY name'
    ),
    insertItem:      d.prepare(
      'INSERT INTO items (id,folder_id,name,username,encrypted_password,password_iv,encrypted_notes,notes_iv,created_at,created_by,modified_at,modified_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    ),
    updateItem:      d.prepare(
      'UPDATE items SET name=?,username=?,encrypted_password=?,password_iv=?,encrypted_notes=?,notes_iv=?,modified_at=?,modified_by=? WHERE id=?'
    ),
    deleteItem:      d.prepare('DELETE FROM items WHERE id = ?'),
    getAllPasswordItems: d.prepare('SELECT id, encrypted_password, password_iv FROM items WHERE encrypted_password IS NOT NULL'),

    // Permissions
    getPermissionsFor:      d.prepare('SELECT * FROM permissions WHERE resource_type=? AND resource_id=?'),
    upsertPermission:       d.prepare(
      'INSERT OR REPLACE INTO permissions (id,resource_type,resource_id,subject_type,subject,level) VALUES (?,?,?,?,?,?)'
    ),
    deletePermission:       d.prepare(
      'DELETE FROM permissions WHERE resource_type=? AND resource_id=? AND subject_type=? AND subject=?'
    ),
    deleteAllPermissionsFor: d.prepare('DELETE FROM permissions WHERE resource_type=? AND resource_id=?'),

    // Audit log
    insertAuditLog:          d.prepare('INSERT INTO audit_log (id,timestamp,actor,ip,action,resource_type,resource_id,resource_name) VALUES (?,?,?,?,?,?,?,?)'),
    getAuditLog:             d.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?'),
    countAuditLog:           d.prepare('SELECT COUNT(*) as count FROM audit_log'),
    getAuditLogForResource:  d.prepare('SELECT * FROM audit_log WHERE resource_type=? AND resource_id=? ORDER BY timestamp DESC LIMIT 200'),
  };
}

function getAncestorIds(folderId) {
  const ancestors = [];
  let current = folderId;
  const seen = new Set();
  while (current) {
    if (seen.has(current)) break;
    seen.add(current);
    const row = getDb().prepare('SELECT parent_id FROM folders WHERE id = ?').get(current);
    if (!row || !row.parent_id) break;
    ancestors.push(row.parent_id);
    current = row.parent_id;
  }
  return ancestors;
}

module.exports = { initDb, getDb, stmts, getAncestorIds };

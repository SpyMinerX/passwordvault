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

    CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
    CREATE INDEX IF NOT EXISTS idx_items_folder   ON items(folder_id);
    CREATE INDEX IF NOT EXISTS idx_perms_resource ON permissions(resource_type, resource_id);
  `);
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

    // Permissions
    getPermissionsFor:      d.prepare('SELECT * FROM permissions WHERE resource_type=? AND resource_id=?'),
    upsertPermission:       d.prepare(
      'INSERT OR REPLACE INTO permissions (id,resource_type,resource_id,subject_type,subject,level) VALUES (?,?,?,?,?,?)'
    ),
    deletePermission:       d.prepare(
      'DELETE FROM permissions WHERE resource_type=? AND resource_id=? AND subject_type=? AND subject=?'
    ),
    deleteAllPermissionsFor: d.prepare('DELETE FROM permissions WHERE resource_type=? AND resource_id=?'),
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

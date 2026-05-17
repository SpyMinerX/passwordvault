'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');

const { stmts } = require('../db');
const { requireAuthApi, resolvePermission, checkPermission, meetsLevel } = require('../middleware');
const { logAudit } = require('../audit');
const config = require('../config');

const router = express.Router();
router.use(requireAuthApi);

// Build the visible tree for the current user
function buildTree(user, parentId) {
  const s = stmts();
  const folders = parentId ? s.getChildFolders.all(parentId) : s.getRootFolders.all();
  const result = [];
  for (const folder of folders) {
    const level = resolvePermission(user, 'folder', folder.id);
    if (level !== null) {
      result.push({
        id: folder.id,
        name: folder.name,
        parent_id: folder.parent_id,
        userLevel: level,
        children: buildTree(user, folder.id),
      });
    }
  }
  return result;
}

// GET /api/folders/tree
router.get('/tree', (req, res) => {
  const tree = buildTree(req.user, null);
  res.json({ tree });
});

// POST /api/folders — create folder
router.post('/', (req, res) => {
  const { name, parentId } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }

  if (!parentId) {
    return res.status(403).json({ error: 'Root folder creation is disabled — only the system root exists' });
  }

  if (parentId) {
    const level = resolvePermission(req.user, 'folder', parentId);
    if (!meetsLevel(level, 'write')) return res.status(403).json({ error: 'Forbidden' });
    const parent = stmts().getFolderById.get(parentId);
    if (!parent) return res.status(404).json({ error: 'Parent folder not found' });
  }

  const id = uuidv4();
  const now = new Date().toISOString();
  stmts().insertFolder.run(id, name.trim(), parentId || null, now, req.user.username);
  logAudit(req, 'create_folder', 'folder', id, name.trim());
  res.status(201).json({ id, name: name.trim(), parent_id: parentId || null });
});

// DELETE /api/folders/debug/root/:id — hidden debug: delete a root folder (GLOBAL_ADMIN only)
router.delete('/debug/root/:id', (req, res) => {
  const u = req.user;
  const ga = config.globalAdmin;
  const isGlobalAdmin = ga && (
    u.username.toLowerCase() === ga ||
    (u.memberOf || []).some(g => g.toLowerCase() === ga)
  );
  if (!isGlobalAdmin) return res.status(403).json({ error: 'GLOBAL_ADMIN required' });

  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Folder not found' });
  if (folder.parent_id) return res.status(400).json({ error: 'Not a root folder — use the normal delete for subfolders' });

  logAudit(req, 'delete_folder', 'folder', folder.id, folder.name);
  stmts().deleteFolder.run(req.params.id);
  console.warn(`[DEBUG] Root folder "${folder.name}" (${folder.id}) deleted by ${u.username}`);
  res.json({ ok: true, deleted: folder.name });
});

function guardRootFolder(res, folder) {
  if (!folder.parent_id) {
    res.status(403).json({ error: 'The root folder cannot be modified' });
    return true;
  }
  return false;
}

// PUT /api/folders/:id — rename
router.put('/:id', checkPermission('folder', r => r.params.id, 'write'), (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }
  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  if (guardRootFolder(res, folder)) return;
  stmts().updateFolder.run(name.trim(), req.params.id);
  logAudit(req, 'rename_folder', 'folder', req.params.id, name.trim());
  res.json({ id: req.params.id, name: name.trim() });
});

// DELETE /api/folders/:id
router.delete('/:id', checkPermission('folder', r => r.params.id, 'admin'), (req, res) => {
  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  if (guardRootFolder(res, folder)) return;
  logAudit(req, 'delete_folder', 'folder', req.params.id, folder.name);
  stmts().deleteFolder.run(req.params.id);
  res.json({ ok: true });
});

// GET /api/folders/:id/permissions
router.get('/:id/permissions', checkPermission('folder', r => r.params.id, 'admin'), (req, res) => {
  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  if (guardRootFolder(res, folder)) return;
  const perms = stmts().getPermissionsFor.all('folder', req.params.id);
  res.json({ permissions: perms });
});

// POST /api/folders/:id/permissions
router.post('/:id/permissions', checkPermission('folder', r => r.params.id, 'admin'), (req, res) => {
  const { subjectType, subject, level } = req.body;
  if (!['group', 'user'].includes(subjectType)) return res.status(400).json({ error: 'invalid subjectType' });
  if (!['read', 'write', 'admin', 'hide'].includes(level)) return res.status(400).json({ error: 'invalid level' });
  if (!subject || typeof subject !== 'string') return res.status(400).json({ error: 'subject required' });
  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  if (guardRootFolder(res, folder)) return;
  const id = uuidv4();
  stmts().upsertPermission.run(id, 'folder', req.params.id, subjectType, subject.trim(), level);
  res.status(201).json({ ok: true });
});

// DELETE /api/folders/:id/permissions
router.delete('/:id/permissions', checkPermission('folder', r => r.params.id, 'admin'), (req, res) => {
  const { subjectType, subject } = req.body;
  if (!subjectType || !subject) return res.status(400).json({ error: 'subjectType and subject required' });
  const folder = stmts().getFolderById.get(req.params.id);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  if (guardRootFolder(res, folder)) return;
  stmts().deletePermission.run('folder', req.params.id, subjectType, subject);
  res.json({ ok: true });
});

// GET /api/folders/:folderId/items — list items (no secrets)
router.get('/:folderId/items', checkPermission('folder', r => r.params.folderId, 'read'), (req, res) => {
  const folder = stmts().getFolderById.get(req.params.folderId);
  if (!folder) return res.status(404).json({ error: 'Not found' });
  const items = stmts().getItemsByFolder.all(req.params.folderId);
  const annotated = items.map(item => ({
    ...item,
    userLevel: resolvePermission(req.user, 'item', item.id),
  })).filter(item => item.userLevel !== null);
  res.json({ items: annotated });
});

// POST /api/folders/:folderId/items — create item
router.post('/:folderId/items', checkPermission('folder', r => r.params.folderId, 'write'), (req, res) => {
  const folder = stmts().getFolderById.get(req.params.folderId);
  if (!folder) return res.status(404).json({ error: 'Not found' });

  const { name, username, password, notes } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }

  const { encrypt } = require('../crypto');
  const encPw = encrypt(password || '');
  const encNotes = encrypt(notes || '');
  const id = uuidv4();
  const now = new Date().toISOString();

  stmts().insertItem.run(
    id, req.params.folderId, name.trim(), (username || '').trim(),
    encPw.ciphertext, encPw.iv,
    encNotes.ciphertext, encNotes.iv,
    now, req.user.username, now, req.user.username
  );

  logAudit(req, 'create_item', 'item', id, name.trim());
  res.status(201).json({ id, name: name.trim(), folder_id: req.params.folderId });
});

module.exports = router;

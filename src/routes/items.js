'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');

const { stmts } = require('../db');
const { encrypt, decrypt } = require('../crypto');
const { requireAuthApi, resolvePermission, checkPermission, meetsLevel } = require('../middleware');
const { logAudit } = require('../audit');

const router = express.Router();
router.use(requireAuthApi);

// POST /api/items/check-password — count how many other items share this plaintext password
router.post('/items/check-password', async (req, res) => {
  const { password, excludeId } = req.body;
  if (!password || typeof password !== 'string') return res.json({ count: 0 });
  const items = stmts().getAllPasswordItems.all();
  let count = 0;
  for (const item of items) {
    if (excludeId && item.id === excludeId) continue;
    if (!item.encrypted_password || !item.password_iv) continue;
    try {
      if (decrypt(item.encrypted_password, item.password_iv) === password) count++;
    } catch { /* skip corrupted entries */ }
  }
  res.json({ count });
});

// GET /api/items/:id — metadata only
router.get('/items/:id', checkPermission('item', r => r.params.id, 'read'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const { encrypted_password, password_iv, encrypted_notes, notes_iv, ...safe } = item;
  res.json({ item: { ...safe, userLevel: resolvePermission(req.user, 'item', item.id) } });
});

// PUT /api/items/:id — update
router.put('/items/:id', checkPermission('item', r => r.params.id, 'write'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });

  const { name, username, password, notes } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }

  let encPw = { ciphertext: item.encrypted_password, iv: item.password_iv };
  if (password !== undefined && password !== '') encPw = encrypt(password);

  let encNotes = { ciphertext: item.encrypted_notes, iv: item.notes_iv };
  if (notes !== undefined) encNotes = encrypt(notes);

  const now = new Date().toISOString();
  stmts().updateItem.run(
    name.trim(), (username || '').trim(),
    encPw.ciphertext, encPw.iv,
    encNotes.ciphertext, encNotes.iv,
    now, req.user.username,
    req.params.id
  );

  logAudit(req, 'edit_item', 'item', req.params.id, name.trim());
  res.json({ ok: true });
});

// DELETE /api/items/:id
router.delete('/items/:id', checkPermission('item', r => r.params.id, 'write'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  logAudit(req, 'delete_item', 'item', req.params.id, item.name);
  stmts().deleteItem.run(req.params.id);
  stmts().deleteOrphanedPermissions.run();
  res.json({ ok: true });
});

// GET /api/items/:id/password — reveal decrypted password
router.get('/items/:id/password', checkPermission('item', r => r.params.id, 'read'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  try {
    const password = decrypt(item.encrypted_password, item.password_iv);
    logAudit(req, 'reveal_password', 'item', item.id, item.name);
    res.json({ password });
  } catch {
    res.status(500).json({ error: 'Decryption failed' });
  }
});

// GET /api/items/:id/notes — reveal decrypted notes
router.get('/items/:id/notes', checkPermission('item', r => r.params.id, 'read'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  try {
    const notes = decrypt(item.encrypted_notes, item.notes_iv);
    logAudit(req, 'reveal_notes', 'item', item.id, item.name);
    res.json({ notes });
  } catch {
    res.status(500).json({ error: 'Decryption failed' });
  }
});

// GET /api/items/:id/permissions
router.get('/items/:id/permissions', checkPermission('item', r => r.params.id, 'admin'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const perms = stmts().getPermissionsFor.all('item', req.params.id);
  res.json({ permissions: perms });
});

// POST /api/items/:id/permissions
router.post('/items/:id/permissions', checkPermission('item', r => r.params.id, 'admin'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const { subjectType, subject, level } = req.body;
  if (!['group', 'user'].includes(subjectType)) return res.status(400).json({ error: 'invalid subjectType' });
  if (!['read', 'write', 'admin', 'hide'].includes(level)) return res.status(400).json({ error: 'invalid level' });
  if (!subject || typeof subject !== 'string') return res.status(400).json({ error: 'subject required' });
  const id = uuidv4();
  stmts().upsertPermission.run(id, 'item', req.params.id, subjectType, subject.trim(), level);
  res.status(201).json({ ok: true });
});

// DELETE /api/items/:id/permissions
router.delete('/items/:id/permissions', checkPermission('item', r => r.params.id, 'admin'), (req, res) => {
  const item = stmts().getItemById.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const { subjectType, subject } = req.body;
  if (!subjectType || !subject) return res.status(400).json({ error: 'subjectType and subject required' });
  stmts().deletePermission.run('item', req.params.id, subjectType, subject);
  res.json({ ok: true });
});

module.exports = router;

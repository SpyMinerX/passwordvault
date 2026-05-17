'use strict';

const express = require('express');
const { stmts } = require('../db');
const { requireAuthApi, resolvePermission, meetsLevel } = require('../middleware');
const config = require('../config');

const router = express.Router();
router.use(requireAuthApi);

function isGlobalAdmin(user) {
  const ga = config.globalAdmin;
  if (!ga) return false;
  return user.username.toLowerCase() === ga ||
    (user.memberOf || []).some(g => g.toLowerCase() === ga);
}

// GET /api/audit — full log (GLOBAL_ADMIN or emergency only)
router.get('/audit', (req, res) => {
  if (!isGlobalAdmin(req.user) && !req.user.isEmergency) {
    return res.status(403).json({ error: 'Global admin required to view full audit log' });
  }
  const limit  = Math.min(parseInt(req.query.limit)  || 100, 500);
  const offset = Math.max(parseInt(req.query.offset) || 0,   0);
  const entries = stmts().getAuditLog.all(limit, offset);
  const countRow = stmts().countAuditLog.get();
  res.json({ entries, total: Number(countRow.count), limit, offset });
});

// GET /api/audit/item/:id — item-specific log (admin on that item)
router.get('/audit/item/:id', (req, res) => {
  const level = resolvePermission(req.user, 'item', req.params.id);
  if (!meetsLevel(level, 'admin') && !isGlobalAdmin(req.user) && !req.user.isEmergency) {
    return res.status(403).json({ error: 'Admin access required to view item history' });
  }
  const entries = stmts().getAuditLogForResource.all('item', req.params.id);
  res.json({ entries });
});

module.exports = router;

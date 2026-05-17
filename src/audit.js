'use strict';

const { randomUUID } = require('crypto');
const { stmts } = require('./db');

function logAudit(req, action, resourceType, resourceId, resourceName) {
  try {
    stmts().insertAuditLog.run(
      randomUUID(),
      new Date().toISOString(),
      req.user?.username || 'unknown',
      req.ip || null,
      action,
      resourceType || null,
      resourceId || null,
      resourceName || null
    );
  } catch (e) {
    console.error('[audit] Failed to write log entry:', e.message);
  }
}

module.exports = { logAudit };

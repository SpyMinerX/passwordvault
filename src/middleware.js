'use strict';

const { stmts } = require('./db');
const config = require('./config');

const LEVEL_RANK = { read: 1, write: 2, admin: 3 };

function meetsLevel(actual, required) {
  return actual !== null && (LEVEL_RANK[actual] || 0) >= (LEVEL_RANK[required] || 0);
}

function findHighestApplicableLevel(user, perms) {
  const userSubjects = new Set([user.username.toLowerCase()]);
  for (const g of (user.memberOf || [])) userSubjects.add(g.toLowerCase());

  for (const tier of ['admin', 'write', 'read']) {
    for (const p of perms) {
      if (p.level !== tier) continue;
      if (p.subject === '*') return tier;  // wildcard = everyone
      if (p.subject_type === 'user' && userSubjects.has(p.subject.toLowerCase())) return tier;
      if (p.subject_type === 'group' && userSubjects.has(p.subject.toLowerCase())) return tier;
    }
  }
  return null;
}

function resolvePermission(user, resourceType, resourceId) {
  // Emergency login and global admin bypass all ACL checks
  if (user.isEmergency) return 'admin';
  if (config.globalAdmin && (user.memberOf || []).some(g => g.toLowerCase() === config.globalAdmin)) return 'admin';

  const s = stmts();
  const perms = s.getPermissionsFor.all(resourceType, resourceId);

  if (perms.length > 0) {
    return findHighestApplicableLevel(user, perms);
  }

  // Inherit from parent
  if (resourceType === 'item') {
    const item = s.getItemById.get(resourceId);
    if (!item) return null;
    return resolvePermission(user, 'folder', item.folder_id);
  }

  if (resourceType === 'folder') {
    const folder = s.getFolderById.get(resourceId);
    if (!folder) return null;
    if (!folder.parent_id) return null; // default: hidden — explicit permissions required
    return resolvePermission(user, 'folder', folder.parent_id);
  }

  return null;
}

function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
}

function requireAuthApi(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function checkPermission(resourceType, getResourceId, requiredLevel) {
  return (req, res, next) => {
    const id = getResourceId(req);
    const level = resolvePermission(req.user, resourceType, id);
    if (meetsLevel(level, requiredLevel)) return next();
    res.status(403).json({ error: 'Forbidden' });
  };
}

module.exports = { requireAuth, requireAuthApi, resolvePermission, checkPermission, meetsLevel };

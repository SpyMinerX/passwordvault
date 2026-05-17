'use strict';

const express = require('express');
const { requireAuthApi } = require('../middleware');
const { searchGroups, searchUsers } = require('../ldap');

const router = express.Router();
router.use(requireAuthApi);

router.get('/groups', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json({ results: [] });
  try {
    const results = await searchGroups(q);
    res.json({ results });
  } catch (err) {
    console.error('LDAP group search failed:', err.message);
    res.status(500).json({ error: 'LDAP search failed' });
  }
});

router.get('/users', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json({ results: [] });
  try {
    const results = await searchUsers(q);
    res.json({ results });
  } catch (err) {
    console.error('LDAP user search failed:', err.message);
    res.status(500).json({ error: 'LDAP search failed' });
  }
});

module.exports = router;

'use strict';

const crypto = require('crypto');
const express = require('express');
const passport = require('passport');
const config = require('../config');

const router = express.Router();

router.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  const error = req.query.error;
  res.render('login', { error: error || null, hasEmergency: !!config.emergencyPassword });
});

function checkEmergencyPassword(submitted) {
  if (!config.emergencyPassword || !submitted) return false;
  // Constant-time comparison to prevent timing attacks
  const a = Buffer.from(submitted);
  const b = Buffer.from(config.emergencyPassword);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  // Emergency login — checked before LDAP so it works even if LDAP is down
  if (config.emergencyPassword && checkEmergencyPassword(password)) {
    const emergencyUser = {
      dn: 'emergency',
      username: (username && username.trim()) || 'emergency',
      displayName: 'Emergency Access',
      memberOf: [],
      isEmergency: true,
    };
    return req.logIn(emergencyUser, (err) => {
      if (err) return next(err);
      const returnTo = req.query.returnTo && req.query.returnTo.startsWith('/')
        ? req.query.returnTo : '/';
      res.redirect(returnTo);
    });
  }

  // Strip domain prefix (e.g. "DOMAIN\user" or "user@domain") → "user"
  if (req.body.username) {
    req.body.username = req.body.username
      .replace(/^.*\\/, '')   // strip "DOMAIN\"
      .replace(/@.*$/, '');   // strip "@domain"
  }

  passport.authenticate('ldapauth', (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      const msg = info && info.message;
      let error = 'invalid';
      if (msg === 'group') error = 'group';
      else if (msg && msg.toLowerCase().includes('connect')) error = 'connect';
      return res.redirect(`/login?error=${error}`);
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      const returnTo = req.query.returnTo && req.query.returnTo.startsWith('/')
        ? req.query.returnTo
        : '/';
      res.redirect(returnTo);
    });
  })(req, res, next);
});

router.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect('/login'));
  });
});

module.exports = router;

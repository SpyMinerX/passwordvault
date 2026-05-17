'use strict';

const LdapStrategy = require('passport-ldapauth').Strategy;
const config = require('./config');

function configurePassport(passport) {
  passport.use(new LdapStrategy({
    server: {
      url: config.ldap.url,
      bindDN: config.ldap.bindDN,
      bindCredentials: config.ldap.bindCredentials,
      searchBase: config.ldap.searchBase,
      searchFilter: config.ldap.searchFilter,
      searchAttributes: ['dn', 'uid', 'sAMAccountName', 'displayName', 'mail', 'memberOf'],
      tlsOptions: { rejectUnauthorized: false },
    },
    passReqToCallback: true,
  }, (req, profile, done) => {
    if (config.ldap.allowedGroup) {
      const memberOf = profile.memberOf || [];
      const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
      const isMember = groups.some(g => g.toLowerCase().includes(config.ldap.allowedGroup.toLowerCase()));
      if (!isMember) return done(null, false, { message: 'group' });
    }

    const memberOf = profile.memberOf || [];
    return done(null, {
      dn: profile.dn,
      username: profile.sAMAccountName || profile.uid || (profile.mail && profile.mail.split('@')[0]) || profile.dn,
      displayName: profile.displayName || profile.sAMAccountName || profile.uid || profile.dn,
      memberOf: Array.isArray(memberOf) ? memberOf : [memberOf],
    });
  }));

  passport.serializeUser((user, done) => done(null, JSON.stringify(user)));
  passport.deserializeUser((data, done) => {
    try { done(null, JSON.parse(data)); }
    catch (e) { done(e); }
  });

  console.log('Passport configured');
}

module.exports = { configurePassport };

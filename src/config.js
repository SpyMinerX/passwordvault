'use strict';

require('dotenv').config();

function loadConfig() {
  const missing = [];

  function require_env(name) {
    const val = process.env[name];
    if (!val) missing.push(name);
    return val || '';
  }

  const cfg = {
    port: parseInt(process.env.PORT || '3000', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
    trustProxy: process.env.TRUST_PROXY !== 'false',
    sessionSecret: require_env('SESSION_SECRET'),
    masterKey: require_env('MASTER_KEY'),
    dbPath: process.env.DB_PATH || './data/passwords.db',
    emergencyPassword: process.env.EMERGENCY_PASSWORD || null,
    globalAdmin: process.env.GLOBAL_ADMIN ? process.env.GLOBAL_ADMIN.toLowerCase() : null,
    rootFolderName: process.env.ROOT_FOLDER_NAME || 'FFManching',
    ldap: {
      url: require_env('LDAP_URL'),
      bindDN: require_env('LDAP_BIND_DN'),
      bindCredentials: require_env('LDAP_BIND_CREDENTIALS'),
      searchBase: require_env('LDAP_SEARCH_BASE'),
      searchFilter: process.env.LDAP_SEARCH_FILTER || '(sAMAccountName={{username}})',
      allowedGroup: process.env.LDAP_ALLOWED_GROUP || null,
    },
  };

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  if (cfg.masterKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(cfg.masterKey)) {
    throw new Error('MASTER_KEY must be exactly 64 hex characters (32 bytes). Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }

  return Object.freeze(cfg);
}

module.exports = loadConfig();

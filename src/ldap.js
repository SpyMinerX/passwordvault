'use strict';

const config = require('./config');

function escapeLdap(str) {
  return str
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\x00/g, '\\00');
}

// Cache the ESM import — dynamic import() works from CommonJS in Node 22
let _Client = null;
async function getClientClass() {
  if (!_Client) {
    const mod = await import('ldapts');
    _Client = mod.Client;
  }
  return _Client;
}

async function withClient(fn) {
  const Client = await getClientClass();
  const client = new Client({
    url: config.ldap.url,
    tlsOptions: { rejectUnauthorized: false },
    timeout: 8000,
  });
  await client.bind(config.ldap.bindDN, config.ldap.bindCredentials);
  try {
    return await fn(client);
  } finally {
    await client.unbind().catch(() => {});
  }
}

// ldapts may return attributes as a string or array — always return first string value
function attr(entry, name) {
  const v = entry[name];
  if (!v) return '';
  return Array.isArray(v) ? (v[0] ?? '') : String(v);
}

async function searchGroups(q) {
  const safe = escapeLdap(q);
  return withClient(async (client) => {
    const { searchEntries } = await client.search(config.ldap.searchBase, {
      filter: `(&(objectClass=group)(cn=*${safe}*))`,
      attributes: ['cn', 'description'],
      sizeLimit: 40,
    });
    return searchEntries.map(e => ({
      dn: e.dn,
      name: attr(e, 'cn'),
      description: attr(e, 'description'),
    }));
  });
}

async function searchUsers(q) {
  const safe = escapeLdap(q);
  return withClient(async (client) => {
    const { searchEntries } = await client.search(config.ldap.searchBase, {
      filter: `(&(objectClass=user)(!(objectClass=computer))(|(sAMAccountName=*${safe}*)(displayName=*${safe}*)(mail=*${safe}*)))`,
      attributes: ['sAMAccountName', 'displayName', 'mail'],
      sizeLimit: 40,
    });
    return searchEntries.map(e => ({
      dn: e.dn,
      username: attr(e, 'sAMAccountName'),
      displayName: attr(e, 'displayName') || attr(e, 'sAMAccountName'),
      mail: attr(e, 'mail'),
    }));
  });
}

module.exports = { searchGroups, searchUsers };

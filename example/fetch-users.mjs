// Fetch all users with the admin account - the search is paged, so more
// than 1000 entries can be returned.
// Requires the bundled seeded test server: `docker compose up -d`
// (or set LDAP_URL to point at your own server).

import { fetchUsers } from '../index.mjs'

const ldapOpts = {
  url: process.env.LDAP_URL || 'ldap://localhost:1389',
}

const baseOptions = {
  ldapOpts,
  adminDn: 'cn=read-only-admin,dc=example,dc=com',
  adminPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
}

// 1. All users (default filter: entries with a uid or sAMAccountName), all attributes
let users = await fetchUsers(baseOptions)
console.log('all users ->', users.map((user) => user.uid ?? user.cn))

// 2. Custom filter + attribute selection
users = await fetchUsers({
  ...baseOptions,
  userFilter: '(uid=gauss)',
  attributes: ['uid', 'sn'],
})
console.log('filtered  ->', users)

// 3. Small page size (paged results are always on)
users = await fetchUsers({
  ...baseOptions,
  pageSize: 1,
})
console.log('paged     ->', users.length, 'entries with pageSize 1')

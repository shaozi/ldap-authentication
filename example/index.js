// Admin and self authentication, with group lookup.
// Requires the bundled seeded test server: `docker compose up -d`
// (or set LDAP_URL to point at your own server).

const { authenticate } = require('../index')

const url = process.env.LDAP_URL || 'ldap://localhost:1389'

async function auth() {
  // 1. Admin mode: bind as admin, find the user, then bind as the user.
  // Restrict `attributes` so the server does not return everything (including
  // userPassword).
  let user = await authenticate({
    ldapOpts: { url },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
    attributes: ['uid', 'sn', 'cn'],
  })
  console.log('admin mode     ->', JSON.stringify(user, null, 2))

  // 2. Self mode: the user binds with its own DN and gets its details
  user = await authenticate({
    ldapOpts: { url },
    userDn: 'cn=einstein,ou=users,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'einstein',
    attributes: ['uid', 'sn'],
  })
  console.log('self mode      ->', { uid: user.uid, sn: user.sn })

  // 3. Admin mode with group lookup
  user = await authenticate({
    ldapOpts: { url },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
    groupsSearchBase: 'dc=example,dc=com',
    groupClass: 'groupOfNames',
    groupMemberAttribute: 'member',
  })
  console.log('with groups    ->', user.groups.map((group) => group.cn))
}

auth().catch((error) => {
  console.error(error)
  process.exit(1)
})

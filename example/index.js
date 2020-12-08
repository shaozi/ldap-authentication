const { authenticate } = require('../index')

async function auth() {
  // auth with admin
  let options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
      // tlsOptions: { rejectUnauthorized: false }
    },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
    // starttls: false
  }

  let user = await authenticate(options)
  console.log(`user = ${JSON.stringify(user, null, 2)}`)

  // auth with regular user
  options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
      // tlsOptions: { rejectUnauthorized: false }
    },
    userDn: 'uid=einstein,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'einstein',
    // starttls: false
  }

  user = await authenticate(options)
  console.log(`user = ${JSON.stringify(user, null, 2)}`)

  // Getting user group info
  options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
    },
    userDn: 'uid=gauss,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
    groupsSearchBase: 'dc=example,dc=com',
    groupClass: 'groupOfUniqueNames',
    groupMemberAttribute: 'uniqueMember',
  }

  user = await authenticate(options)
  console.log(`user = ${JSON.stringify(user, null, 2)}`)
}

auth()

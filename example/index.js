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
    userSearchString: '(uid=gauss)',
    // starttls: false
  }
  
  let user = await authenticate(options)
  console.log(user)

  // auth with regular user
  options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
      // tlsOptions: { rejectUnauthorized: false }
    },
    userDn: 'uid=einstein,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    userSearchString: '(uid=einstein)',
    // starttls: false
  }

  user = await authenticate(options)
  console.log(user)
}

auth()
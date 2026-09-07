// Verify that a user exists (without checking the password).
// Requires the bundled seeded test server: `docker compose up -d`
// (or set LDAP_URL to point at your own server).

const { authenticate, LdapAuthenticationError } = require('../index')

const url = process.env.LDAP_URL || 'ldap://localhost:1389'

async function verify() {
  // Existing user
  let user = await authenticate({
    ldapOpts: { url },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    verifyUserExists: true,
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
  })
  console.log('gauss exists ->', user.uid)

  // Non-existing user throws LdapAuthenticationError
  try {
    await authenticate({
      ldapOpts: { url },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      verifyUserExists: true,
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'does-not-exist',
    })
  } catch (error) {
    if (error instanceof LdapAuthenticationError) {
      console.log('does-not-exist ->', error.message)
    } else {
      throw error
    }
  }
}

verify().catch((error) => {
  console.error(error)
  process.exit(1)
})

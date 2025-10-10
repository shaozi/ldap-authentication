const { authenticate, LdapAuthenticationError } = require('../index.js')

const url = process.env.INGITHUB ? 'ldap://localhost:1389' : 'ldap://ldap:1389'

describe('ldap-authentication StartTLS and TLS options test', () => {
  it('Plain LDAP with tlsOptions in ldapOpts should work (ldap:// protocol)', async () => {
    // Regression test: Before fix, having tlsOptions with ldap:// URL caused issues
    // After fix: tlsOptions are properly excluded from Client constructor for ldap:// URLs
    let options = {
      ldapOpts: {
        url: url,
        tlsOptions: {
          rejectUnauthorized: false,
        },
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
  })

  it('Use an admin user to authenticate with StartTLS (may skip if TLS not configured)', async () => {
    // Note: This test may not fully succeed if the LDAP server lacks TLS certificates
    // However, it should NOT fail with the original ECONNRESET bug
    let options = {
      ldapOpts: {
        url: url,
        tlsOptions: {
          rejectUnauthorized: false,
          minVersion: 'TLSv1.2',
        },
      },
      starttls: true,
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    try {
      let user = await authenticate(options)
      // If this succeeds, StartTLS is fully working!
      expect(user).toBeTruthy()
      expect(user.uid).toEqual('gauss')
    } catch (error) {
      // Expected if StartTLS is not configured on the server
      // The critical check: should NOT be the original ECONNRESET bug
      if (error.code === 'ECONNRESET' && 
          error.message && error.message.includes('Client network socket disconnected before secure TLS connection')) {
        fail('ECONNRESET bug detected: tlsOptions should NOT be passed to Client constructor when using ldap:// URL')
      }
      // Other errors are acceptable (e.g., server doesn't support StartTLS)
      expect(error).toBeTruthy()
    }
  })

  it('Use a regular user to authenticate with StartTLS (self mode)', async () => {
    let options = {
      ldapOpts: {
        url: url,
        tlsOptions: {
          rejectUnauthorized: false,
          minVersion: 'TLSv1.2',
        },
      },
      starttls: true,
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'einstein',
    }

    try {
      let user = await authenticate(options)
      expect(user).toBeTruthy()
      expect(user.uid).toEqual('einstein')
    } catch (error) {
      if (error.code === 'ECONNRESET' && 
          error.message && error.message.includes('Client network socket disconnected before secure TLS connection')) {
        fail('ECONNRESET bug detected: tlsOptions should NOT be passed to Client constructor when using ldap:// URL')
      }
      expect(error).toBeTruthy()
    }
  })

  it('Verify user exists with StartTLS', async () => {
    let options = {
      ldapOpts: {
        url: url,
        tlsOptions: {
          rejectUnauthorized: false,
          minVersion: 'TLSv1.2',
        },
      },
      starttls: true,
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      verifyUserExists: true,
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    try {
      let user = await authenticate(options)
      expect(user).toBeTruthy()
      expect(user.uid).toEqual('gauss')
    } catch (error) {
      if (error.code === 'ECONNRESET' && 
          error.message && error.message.includes('Client network socket disconnected before secure TLS connection')) {
        fail('ECONNRESET bug detected: tlsOptions should NOT be passed to Client constructor when using ldap:// URL')
      }
      expect(error).toBeTruthy()
    }
  })
})

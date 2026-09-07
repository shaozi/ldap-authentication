const {
  authenticate,
  LdapAuthenticationError,
  AUTH_RESULT_FAILURE,
  AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
  AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
} = require('../index.js')
const { url, adminDn, adminPassword, userSearchBase } = require('./config')

describe('ldap-authentication test', () => {
  it('Use an admin user to check if user exists', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      verifyUserExists: true,
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
  })
  it('Use an admin user to check if user exists and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      verifyUserExists: true,
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      attributes: ['uid', 'sn'],
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
    expect(user.sn).toEqual('Bar1')
    expect(user.cn).toBeUndefined()
  })
  it('Use an admin user to authenticate a regular user', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
  })
  it('Use an admin user to authenticate a regular user and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      attributes: ['uid', 'sn'],
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
    expect(user.sn).toEqual('Bar1')
    expect(user.cn).toBeUndefined()
  })
  it('Use an admin user to authenticate a user with a comma in the CN (e2e of the DN escaping)', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'doe',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('doe')
    // the admin finds `cn=Doe, John,ou=users,...` and must bind with the
    // comma-escaped DN to succeed
    expect(user.cn).toEqual('Doe, John')
    expect(user.dn).toContain('cn=Doe')
    expect(user.dn).toContain('ou=users,dc=example,dc=com')
  })
  it('Use an regular user to authenticate iteself', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'einstein',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('einstein')
  })
  it('Use an regular user to authenticate iteself and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'einstein',
      attributes: ['uid', 'sn'],
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('einstein')
    expect(user.sn).toEqual('Bar2')
    expect(user.cn).toBeUndefined()
  })
  it('Use an regular user to authenticate iteself without search', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
  })
  it('Use an admin user to authenticate a regular user and fetch user group information', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: userSearchBase,
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dn',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeGreaterThan(0)
    expect(user.groups[0].dn).toEqual('cn=科学A部,ou=groups,dc=example,dc=com')
  })
  it('Use regular user to authenticate and fetch user group information', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: userSearchBase,
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dn',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeGreaterThan(0)
    expect(user.groups[0].dn).toEqual('cn=科学A部,ou=groups,dc=example,dc=com')
    // backward compatible with 3.2
    expect(user.groups[0].objectName).toEqual(
      'cn=科学A部,ou=groups,dc=example,dc=com'
    )
  })
  it('Not specifying groupMemberAttribute or groupMemberUserAttribute should not cause an error and fallback to default values', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: userSearchBase,
      groupClass: 'groupOfUniqueNames',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeLessThan(1)
  })
})

describe('ldap-authentication negative test', () => {
  it('wrong admin user should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=not-exist,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
    expect(e.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('wrong admin password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: '',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    // '' is a falsy value, so this exercises the options validation, not the server
    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })
  it('admin auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'wrong',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
    expect(e.code).toEqual(AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND)
  })
  it('admin auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: adminDn,
      adminPassword: adminPassword,
      userPassword: 'wrongpassword',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
    expect(e.code).toEqual(AUTH_RESULT_FAILURE_CREDENTIAL_INVALID)
  })
  it('user auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=not-exist,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })
  it('user auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=gauss,dc=example,dc=com',
      userPassword: 'wrongpassword',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })
  it('Use an regular user to authenticate iteself without search with wrong password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'uid=einstein,dc=example,dc=com',
      userPassword: '',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    // '' is a falsy value, so this exercises the options validation, not the server
    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })
  it('Wrong options give LdapAuthenticationError', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      usernameAttribute: 'wrongattribute',
      userSearchBase: userSearchBase,
      username: 'einstein',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })
  it('Unreachable ldap server should throw error', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://x.forumsys.com',
        connectTimeout: 2000,
      },
      userDn: 'uid=einstein,dc=example,dc=com',
      userPassword: 'password',
      usernameAttribute: 'cn',
      userSearchBase: userSearchBase,
      username: 'einstein',
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
  })
  it('Unreachable ldap server should throw error (with starttls=true)', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://x.forumsys.com',
        connectTimeout: 2000,
      },
      userDn: 'uid=einstein,dc=example,dc=com',
      userPassword: 'password',
      usernameAttribute: 'cn',
      userSearchBase: userSearchBase,
      username: 'einstein',
      starttls: true,
    }

    let e = null
    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
  })
  it('Unmatched supplied groupMemberUserAttribute should return empty group list', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: userSearchBase,
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: userSearchBase,
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dnWRONG',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeLessThan(1)
  })
  it('Missing required options should throw LdapAuthenticationError listing all of them', async () => {
    let e = null
    try {
      await authenticate({
        ldapOpts: {
          url: url,
        },
        adminDn: adminDn,
        usernameAttribute: 'uid',
        username: 'gauss',
      })
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
    // all missing fields are reported at once, not one assert at a time
    expect(e.message).toContain('adminPassword')
    expect(e.message).toContain('userSearchBase')
    expect(e.message).toContain('userPassword')
  })
  it('No adminDn and no userDn should throw LdapAuthenticationError', async () => {
    let e = null
    try {
      await authenticate({
        ldapOpts: {
          url: url,
        },
        userPassword: 'password',
      })
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
    expect(e.message).toContain('adminDn or userDn')
  })
})

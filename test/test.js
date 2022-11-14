const { authenticate, LdapAuthenticationError } = require('../index.js')

describe('ldap-authentication test', () => {
  it('Use an admin user to check if user exists', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      verifyUserExists: true,
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
  })
  it('Use an admin user to authenticate a regular user', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
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
  it('Use an admin user to authenticate a regular user and return attrubutes', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
  it('Use an regular user to authenticate iteself', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
        url: 'ldap://localhost:1389',
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
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: 'dc=example,dc=com',
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dn',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeGreaterThan(0)
  })
  it('Use regular user to authenticate and fetch user group information', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: 'dc=example,dc=com',
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dn',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeGreaterThan(0)
  })
  it('Not specifying groupMemberAttribute or groupMemberUserAttribute should not cause an error and fallback to default values', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: 'dc=example,dc=com',
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
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=not-exist,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('wrong admin password should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: '',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('admin auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('admin auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'wrongpassword',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('user auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=not-exist,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('user auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=gauss,dc=example,dc=com',
      userPassword: 'wrongpassword',
      userSearchBase: 'dc=example,dc=com',
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
  })
  it('Use an regular user to authenticate iteself without search with wrong password should fail', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'uid=einstein,dc=example,dc=com',
      userPassword: '',
    }

    try {
      await authenticate(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
  })
  it('Wrong options give LdapAuthenticationError', async () => {
    let options = {
      ldapOpts: {
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      usernameAttribute: 'wrongattribute',
      userSearchBase: 'dc=example,dc=com',
      username: 'einstein',
    }

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
      userSearchBase: 'dc=example,dc=com',
      username: 'einstein',
    }

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
      userSearchBase: 'dc=example,dc=com',
      username: 'einstein',
      starttls: true,
    }

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
        url: 'ldap://localhost:1389',
      },
      userDn: 'cn=gauss,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: 'dc=example,dc=com',
      groupClass: 'groupOfNames',
      groupMemberAttribute: 'member',
      groupMemberUserAttribute: 'dnWRONG',
    }

    let user = await authenticate(options)
    expect(user).toBeTruthy()
    expect(user.groups.length).toBeLessThan(1)
  })
})

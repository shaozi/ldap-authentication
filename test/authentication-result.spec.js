const {
  authenticateResult,
  AuthenticationResult,
  AUTH_RESULT_SUCCESS,
  AUTH_RESULT_FAILURE,
  AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
  AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
  AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
  AUTH_RESULT_FAILURE_UNCATEGORIZED
} = require('../index.js')

const url = process.env.INGITHUB ? 'ldap://localhost:1389' : 'ldap://ldap:1389'

describe('ldap-authentication test return AuthenticationResult', () => {
  it('Use an admin user to check if user exists', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      verifyUserExists: true,
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('gauss')
  })
  it('Use an admin user to check if user exists and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      verifyUserExists: true,
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      attributes: ['uid', 'sn'],
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('gauss')
    expect(result.user.sn).toEqual('Bar1')
    expect(result.user.cn).toBeUndefined()
  })
  it('Use an admin user to authenticate a regular user', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('gauss')
  })
  it('Use an admin user to authenticate a regular user and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      attributes: ['uid', 'sn'],
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('gauss')
    expect(result.user.sn).toEqual('Bar1')
    expect(result.user.cn).toBeUndefined()
  })
  it('Use an regular user to authenticate iteself', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'einstein',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('einstein')
  })
  it('Use an regular user to authenticate iteself and return attributes', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'einstein',
      attributes: ['uid', 'sn'],
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.uid).toEqual('einstein')
    expect(result.user.sn).toEqual('Bar2')
    expect(result.user.cn).toBeUndefined()
  })
  it('Use an regular user to authenticate iteself without search', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
    }

    let result = await authenticateResult(options)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
  })
  it('Use an admin user to authenticate a regular user and fetch user group information', async () => {
    let options = {
      ldapOpts: {
        url: url,
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

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.groups.length).toBeGreaterThan(0)
    expect(result.user.groups[0].dn).toEqual('cn=科学A部,ou=groups,dc=example,dc=com')
  })
  it('Use regular user to authenticate and fetch user group information', async () => {
    let options = {
      ldapOpts: {
        url: url,
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

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.groups.length).toBeGreaterThan(0)
    expect(result.user.groups[0].dn).toEqual('cn=科学A部,ou=groups,dc=example,dc=com')
    // backward compatible with 3.2
    expect(result.user.groups[0].objectName).toEqual(
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
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
      groupsSearchBase: 'dc=example,dc=com',
      groupClass: 'groupOfUniqueNames',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_SUCCESS)
    expect(result.user).toBeTruthy()
    expect(result.user.groups.length).toBeLessThan(1)
  })
})

describe('ldap-authentication negative test returns AuthenticationResult', () => {
  it('wrong admin user should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=not-exist,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('wrong admin password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'wrongpassword',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('admin auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'wrong',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND)
  })
  it('admin auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
      userPassword: 'wrongpassword',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE_CREDENTIAL_INVALID)
  })
  it('user auth wrong username should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=not-exist,dc=example,dc=com',
      userPassword: 'password',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('user auth wrong user password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=gauss,dc=example,dc=com',
      userPassword: 'wrongpassword',
      userSearchBase: 'dc=example,dc=com',
      usernameAttribute: 'uid',
      username: 'gauss',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('Use an regular user to authenticate iteself without search with wrong password should fail', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'uid=einstein,dc=example,dc=com',
      userPassword: 'wrongpassword',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('Wrong attributes give failure', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      userDn: 'cn=einstein,ou=users,dc=example,dc=com',
      userPassword: 'password',
      usernameAttribute: 'wrongattribute',
      userSearchBase: 'dc=example,dc=com',
      username: 'einstein',
    }

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('Unreachable ldap server should return failure', async () => {
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

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('Unreachable ldap server should return failure (with starttls=true)', async () => {
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

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.code).toEqual(AUTH_RESULT_FAILURE)
  })
  it('Unmatched supplied groupMemberUserAttribute should return empty group list', async () => {
    let options = {
      ldapOpts: {
        url: url,
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

    let result = await authenticateResult(options)
    expect(result).toBeInstanceOf(AuthenticationResult)
    expect(result.user).toBeTruthy()
    expect(result.user.groups.length).toBeLessThan(1)
  })
})

describe('AuthenticationResult', () => {
  it('AuthenticationResult creation and getters', async () => {
    const result = new AuthenticationResult(
      AUTH_RESULT_SUCCESS,
      'testuser',
      { cn: 'Test User' },
      ['Authentication successful'],
      {}
    )

    expect(result.code).toBe(AUTH_RESULT_SUCCESS)
    expect(result.identity).toBe('testuser')
    expect(result.user).toEqual({ cn: 'Test User' })
    expect(result.messages).toEqual(['Authentication successful'])
  })
})

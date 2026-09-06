const { fetchUsers, LdapAuthenticationError } = require('../index.js')

const url = process.env.INGITHUB ? 'ldap://localhost:1389' : 'ldap://ldap:1389'

describe('ldap-authentication fetchUsers test', () => {
  const baseOptions = {
    ldapOpts: {
      url: url,
    },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
  }

  it('Should return all users with the default filter', async () => {
    let users = await fetchUsers(baseOptions)

    expect(Array.isArray(users)).toBe(true)
    expect(users.length).toBe(2)
    let uids = users.map((user) => user.uid)
    expect(uids).toContain('gauss')
    expect(uids).toContain('einstein')
    for (let user of users) {
      expect(user.dn).toBeTruthy()
    }
  })

  it('Should return only the requested attributes', async () => {
    let users = await fetchUsers({
      ...baseOptions,
      attributes: ['uid', 'sn'],
    })

    expect(users.length).toBe(2)
    let gauss = users.find((user) => user.uid === 'gauss')
    expect(gauss).toBeTruthy()
    expect(gauss.sn).toEqual('Bar1')
    expect(gauss.cn).toBeUndefined()
  })

  it('Should return only matching users with a custom userFilter', async () => {
    let users = await fetchUsers({
      ...baseOptions,
      userFilter: '(uid=gauss)',
    })

    expect(users.length).toBe(1)
    expect(users[0].uid).toEqual('gauss')
    expect(users[0].sn).toEqual('Bar1')
  })

  it('Should return all entries including non-users when userFilter matches everything', async () => {
    let users = await fetchUsers({
      ...baseOptions,
      userFilter: '(objectClass=*)',
    })

    expect(users.length).toBeGreaterThan(2)
    let dns = users.map((user) => user.dn)
    expect(dns).toContain('cn=gauss,ou=users,dc=example,dc=com')
    expect(dns).toContain('cn=科学A部,ou=groups,dc=example,dc=com')
  })

  it('Should return empty list when userFilter matches nothing', async () => {
    let users = await fetchUsers({
      ...baseOptions,
      userFilter: '(uid=does-not-exist)',
    })

    expect(users).toEqual([])
  })
})

describe('ldap-authentication fetchUsers negative test', () => {
  const baseOptions = {
    ldapOpts: {
      url: url,
    },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
  }

  it('wrong admin password should throw LdapAuthenticationError', async () => {
    let options = {
      ...baseOptions,
      adminPassword: 'wrongpassword',
    }

    let e = null
    try {
      await fetchUsers(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })

  it('wrong admin dn should throw LdapAuthenticationError', async () => {
    let options = {
      ...baseOptions,
      adminDn: 'cn=not-exist,dc=example,dc=com',
    }

    let e = null
    try {
      await fetchUsers(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
    expect(e).toBeInstanceOf(LdapAuthenticationError)
  })

  it('missing userSearchBase should throw', async () => {
    let options = {
      ldapOpts: {
        url: url,
      },
      adminDn: 'cn=read-only-admin,dc=example,dc=com',
      adminPassword: 'password',
    }

    let e = null
    try {
      await fetchUsers(options)
    } catch (error) {
      e = error
    }

    expect(e).toBeTruthy()
  })
})

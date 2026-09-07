const fs = require('fs')
const path = require('path')
const { Change, Attribute } = require('ldapts')
const { authenticate } = require('../index.js')
const ldapts = require('ldapts')
const { url, adminDn, adminPassword, userSearchBase } = require('./config')

const jpegPhotoBase64 = fs
  .readFileSync(path.join(__dirname, 'fixtures', 'jpeg-photo.b64'), 'utf8')
  .trim()

describe('ldap-authentication binary attributes test', () => {
  const baseOptions = {
    ldapOpts: {
      url: url,
    },
    adminDn: adminDn,
    adminPassword: adminPassword,
    verifyUserExists: true,
    userSearchBase: userSearchBase,
    usernameAttribute: 'uid',
  }

  it('Add jpegPhoto attribute', async () => {
    let client = new ldapts.Client({
      ...baseOptions.ldapOpts,
    })
    try {
      await client.bind(baseOptions.adminDn, baseOptions.adminPassword)

      // https://github.com/ldapts/ldapts/issues/12
      await client.modify(
        'cn=gauss,ou=users,dc=example,dc=com',
        new Change({
          operation: 'replace',
          modification: new Attribute({
            type: 'jpegPhoto',
            values: [Buffer.from(jpegPhotoBase64, 'base64')],
          }),
        })
      )
    } finally {
      await client.unbind()
    }
  })

  it('Should return broken jpegPhoto attribute (no attribute selection nor ;binary) - But it really depends on LDAP server, it is not always true. Sometimes a buffer is returned directly.', async () => {
    let user = await authenticate({
      ...baseOptions,
      username: 'gauss',
    })

    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
    expect(user.sn).toEqual('Bar1')
    expect(typeof user.uidNumber === 'string').toBe(true)
    expect(user.uidNumber).toEqual('1000')

    expect(user.jpegPhoto).toBeDefined()
    // some ldap server returns a string, some ldap server returns a buffer
    expect(
      typeof user.jpegPhoto === 'string' || Buffer.isBuffer(user.jpegPhoto)
    ).toBe(true)
    if (typeof user.jpegPhoto === 'string') {
      expect(user.jpegPhoto).not.toEqual(jpegPhotoBase64)
    }
    if (Buffer.isBuffer(user.jpegPhoto)) {
      expect(
        user.jpegPhoto.equals(Buffer.from(jpegPhotoBase64, 'base64'))
      ).toBeTrue()
    }
  })

  it('Should return nothing in the base64 jpegPhoto (using ;binary)', async () => {
    let user = await authenticate({
      ...baseOptions,
      username: 'gauss',
      attributes: ['uid', 'sn', 'jpegPhoto;binary'],
    })

    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
    expect(user.sn).toEqual('Bar1')
    expect(user.cn).toBeUndefined()

    expect(user.jpegPhoto).toBeUndefined()

    expect(user['jpegPhoto;binary']).toBeDefined()
    expect(Array.isArray(user['jpegPhoto;binary'])).toBe(true)
    expect(user['jpegPhoto;binary'].length).toBe(0)
  })

  it('Should return base64 jpegPhoto (using explicitBufferAttributes)', async () => {
    let user = await authenticate({
      ...baseOptions,
      username: 'gauss',
      attributes: ['uid', 'sn', 'jpegPhoto'],
      explicitBufferAttributes: ['jpegPhoto'],
    })

    expect(user).toBeTruthy()
    expect(user.uid).toEqual('gauss')
    expect(user.sn).toEqual('Bar1')
    expect(user.cn).toBeUndefined()

    expect(user['jpegPhoto;binary']).toBeUndefined()

    expect(user.jpegPhoto).toBeDefined()
    expect(typeof user.jpegPhoto === 'string').toBe(true)
    expect(user.jpegPhoto).toEqual(jpegPhotoBase64)

    const buffer = Buffer.from(user.jpegPhoto, 'base64')
    expect(buffer).toBeDefined()
    expect(buffer.length).toBeGreaterThan(0)
  })
})

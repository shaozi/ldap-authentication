const { Change } = require('ldapts')
const { authenticate, LdapAuthenticationError } = require('../index.js')
const ldapts = require('ldapts')
const { Attribute } = require('ldapts')

const url = process.env.INGITHUB ? 'ldap://localhost:1389' : 'ldap://ldap:1389'

describe('ldap-authentication binary attributes test', () => {
  const jpegPhotoBase64 =
    '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDACgcHiMeGSgjISMtKygwPGRBPDc3PHtYXUlkkYCZlo+AjIqgtObDoKrarYqMyP/L2u71////m8H////6/+b9//j/2wBDASstLTw1PHZBQXb4pYyl+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj4+Pj/wAARCACBAGQDAREAAhEBAxEB/8QAGQAAAwEBAQAAAAAAAAAAAAAAAAECAwQF/8QALRAAAgEDAwMCBQQDAAAAAAAAAAECAxEhBBIxMkFRInEFE2GBsRU0QlJikaH/xAAXAQEBAQEAAAAAAAAAAAAAAAAAAQID/8QAGxEBAQEAAwEBAAAAAAAAAAAAAAERAhIhMUH/2gAMAwEAAhEDEQA/APMIAAKAgChp2AdwAAACBlAQUkmu5RkAAACuAAADsAZQDWQKRA7AL7gAEFCbAQDAYAAXAdwBYAogAAAAgokBgADAEr8Ab09JWqZcdq8yJpjb9Pa5qr/ROy4l6Ga6ZxfvgdoYiemqw6o49yoyAAACCiQKa4AAN9PpnWy3aP5Jbiya9ClRhBJRjby/Ji1qRqRQBMkuwMZSk2trdiys2PPqR2zaNspAAIKE0A+yA201H51TPSuSW4smvTilFJJWSOdbi0RTZQghPgK56nNwzXLXtvx4NxhiUAEABQ0nJpJcgejpkoR2rtyznWo3uRpE5S4i8hfRCrPKm0wLlUUUrgZSruXTD/oROZPISuat1s3GGRQgIKADp0kFNy8pYM2rJrshBQ4M1qNErojTOdFyjZTcfqhKWaqFPObuyAdeKlBfRhcZrT01JzXdWsXWc/U7XF5IVlqWm1waYczKhXKIKEB0aOW2uvDwZvxZ9ejbBlq+CLsZaWrMAckvSgpSW6DQVNKW6ObXRUTVd5BmuKp1M05s2USBmaABpS60Qeg41rqUXeMcszjW61auroliyi7sZaFk1YKirVnSVopyXkqajTNtSv3YouXU/oWM8nHLLZWENFCsBiaAB1aCj86tnpjlko9javBlUVY29SWO4VizNaiVBJcu/m5FJwvyFTGmqct+Como3Juz5EZrnZplLKhWAw5NDZxisW47gen8NpqOncsepmarrIBZwwOWunSf+L4ZmxqVnvI1puoU1nObs347BLS7FZLZ8x27sIwqQcJuMuUaRAGdKN5X8ZKHJu+Qrq02venpbNilnGbDB3UNXHUJ7dqmv4szfA46luVnTbf0ZNFyqUpxcKnpv2kUclWiqT9LvF8O5mtRNnZO+ChSTccAOzsGShVhSlullrhFHPObnNyfLKiAHQW2lKfngqxk3dgSyhwm4TUk3dPDIPV0OrhWltmlGr2fkxYrqrUVVg0+ez8GdHPGhLa0/uaRMFeW1K9wrd6e7vJ2XhFRjKnGqtlNtPyyTB5MrqV28nRFxnf3JgogSqp0FBKzRVZlAEKKyFCbjO6eUQexotaq6UKjtUXf+xz5ccWOmas91u2RKVjHZSlaTe210yoipqHNbY3UfyTVEI7nbyUc+r0vLiuFc1Kjz7WNItSxkmCShAAAgCeXewURbTusNBHs6LWRrpQqO1T8nOzGmtamnG1unK9gM4UknfgqNYxSzZsBuTtiOL2ZKPJ1lFU6zt0yymblRhYonuQD4KEAAOXIUkEa6f8AcQ90Sq92r2+5zioXWvY0jQqJkRXn/EeiHuywcS4NI//Z'

  const baseOptions = {
    ldapOpts: {
      url: url,
    },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    verifyUserExists: true,
    userSearchBase: 'dc=example,dc=com',
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

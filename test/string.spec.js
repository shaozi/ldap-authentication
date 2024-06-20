const { exportForTesting } = require('../index.js')
const { _isHex, _parseEscapedHexToUtf8, _recursiveParseHexString } =
  exportForTesting

describe('string conversion test', () => {
  it('unescape string test', () => {
    let s =
      'cn=\\e7\\a0\\94\\e5\\8f\\91A\\e9\\83\\a8,ou=users,dc=example,dc=com'
    let us = _parseEscapedHexToUtf8(s)
    expect(us).toEqual('cn=研发A部,ou=users,dc=example,dc=com')
  })
  it('unescape string test2', () => {
    let s =
      'cn=\\e7\\a0\\94\\e5\\8f\\91A\\e9\\83\\a8\\c2\\a9,ou=users,dc=example,dc=com'
    let us = _parseEscapedHexToUtf8(s)
    expect(us).toEqual('cn=研发A部©,ou=users,dc=example,dc=com')
  })
  it('unescape string test3', () => {
    let s = 'cn=ABC,ou=users,dc=example,dc=com'
    let us = _parseEscapedHexToUtf8(s)
    expect(us).toEqual('cn=ABC,ou=users,dc=example,dc=com')
  })
  it('convert obj', () => {
    let target = {
      a: ['研发A部©', 'abc'],
      b: 'xyz',
      c: true,
      d: null,
      e: '研发A部©',
      f: 1000,
    }
    let obj = {
      a: ['\\e7\\a0\\94\\e5\\8f\\91A\\e9\\83\\a8\\c2\\a9', 'abc'],
      b: 'xyz',
      c: true,
      d: null,
      e: '\\e7\\a0\\94\\e5\\8f\\91A\\e9\\83\\a8\\c2\\a9',
      f: 1000,
    }
    let converted = _recursiveParseHexString(obj)
    expect(converted).toEqual(target)
  })
})

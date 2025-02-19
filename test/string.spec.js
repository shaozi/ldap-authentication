const { exportForTesting } = require('../index.js')
const { _ldapEscapeDN } = exportForTesting

describe('escape , in the DN test', () => {
  let cases = [
    { s: 'a', want: 'a' },
    { s: '', want: '' },
    { s: 'CN=a,DN=b', want: 'CN=a,DN=b' },
    { s: 'CN=a, c,DN=b', want: 'CN=a\\, c,DN=b' },
    { s: 'CN=a\\, c,DN=b', want: 'CN=a\\, c,DN=b' },
    { s: 'CN=a, b, c,DN=b', want: 'CN=a\\, b\\, c,DN=b' },
    { s: 'CN=a, c', want: 'CN=a\\, c' },
  ]
  for (let c of cases) {
    it('escape ' + c.s, () => {
      let got = _ldapEscapeDN(c.s)
      expect(got).toEqual(c.want)
    })
  }
})


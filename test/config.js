// Shared settings for the integration specs: the LDAP URL (switched to
// localhost:1389 when INGITHUB is set, i.e. outside the docker network) and
// the seeded admin account (see docker/ldap/10-ldap-test-data.ldif).
module.exports = {
  url: process.env.INGITHUB ? 'ldap://localhost:1389' : 'ldap://ldap:1389',
  adminDn: 'cn=read-only-admin,dc=example,dc=com',
  adminPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
}

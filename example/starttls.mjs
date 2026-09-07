// Authenticate over STARTTLS (ldap:// URL upgraded to TLS).
// Requires an LDAP server that supports TLS certificates.
// (The bundled test container generates TLS config but does not enable it,
// so this script prints a notice instead of failing in that case.)

import { authenticate } from '../index.mjs'

const isTlsNotSupported = (error) =>
  error instanceof Error &&
  /secure TLS connection was established/i.test(error.message)

// The bundled container uses a self-signed certificate, so the test
// disables certificate verification. Do NOT do this in production;
// provide your CA in tlsOptions.ca instead.
try {
  const user = await authenticate({
    ldapOpts: {
      url: process.env.LDAP_URL || 'ldap://localhost:1389',
      tlsOptions: {
        rejectUnauthorized: false, // self-signed certificate (test only)
      },
    },
    starttls: true, // upgrade the ldap:// connection to TLS
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
  })
  console.log('starttls auth ->', user.uid)
} catch (error) {
  if (isTlsNotSupported(error)) {
    console.log('This LDAP server does not support TLS - STARTTLS could not be established.')
    console.log('Run this example against a server with TLS enabled (or use an ldaps:// URL).')
  } else {
    console.error(error)
    process.exit(1)
  }
}

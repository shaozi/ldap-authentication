# A Simple node Library that Authenticates a User Against an LDAP/AD Server

[![Integration Tests](https://github.com/shaozi/ldap-authentication/actions/workflows/integration-test.yml/badge.svg)](https://github.com/shaozi/ldap-authentication/actions/workflows/integration-test.yml)
[![Known Vulnerabilities](https://snyk.io/test/github/shaozi/ldap-authentication/badge.svg?targetFile=package.json)](https://snyk.io/test/github/shaozi/ldap-authentication?targetFile=package.json)
[![NPM Weekly Downloads](https://img.shields.io/npm/dw/ldap-authentication?logo=npm)](https://img.shields.io/npm/dw/ldap-authentication?logo=npm)

## Goal

Make authentication with an LDAP server easy.

## Description

This library use `ldapts` as the underneath library. It has three modes of authentications:

1. **Admin authenticate mode**. If an admin user is provided, the library will login (ldap bind) with the admin user,
   then search for the user to be authenticated, get its DN (distinguish name), then use
   the user DN and password to login again. If every thing is ok, the user details will
   be returned.

2. **Self authenticate mode**. If the admin user is not provided, then the `userDn` and `userPassword` must be provided.
   If any of `userSearchBase` or `usernameAttribute` is missing, then the lib simply does a login with
   the `userDn` and `userPassword` (ldap bind), and returns true if succeeds.

   Otherwise, the lib does a login with the `userDn` and `userPassword` (ldap bind),
   then does a search on the user and return the user's details.

3. **Verify user exists**. If an `verifyUserExists : true` is provided, the library will login (ldap bind) with the admin user,
    then search for the user to be verified. If the user exists, user details will be returned (without verifying the user's password).

In addition, the `fetchUsers()` function can be used to fetch all users under a search base, using the admin
account to search (without any username or password of the individual users). The search always uses
LDAP paged results, so the common server-side limit of 1000 entries per search does not apply.

## Features

- Can use an admin to search and authenticate a user
- Can also use a regular user and authenticate the user itself
- Supports ldap, ldaps, and STARTTLS
- Async/Await Promise

## Usage

### Installation

```sh
npm install ldap-authentication --save
```

### Examples

- An example on how to use with Passport is [passport-ldap-example](https://github.com/shaozi/passport-ldap-example)

- Another simple library [express-passport-ldap-mongoose](https://github.com/shaozi/express-passport-ldap-mongoose) provide turn key solution

#### User authenticate without getting user details

```javascript
let authenticated = await authenticate({
  ldapOpts: { url: 'ldap://ldap.forumsys.com' },
  userDn: 'uid=gauss,dc=example,dc=com',
  userPassword: 'password',
})
```

#### User authenticate and return user details

```javascript
let authenticated = await authenticate({
  ldapOpts: { url: 'ldap://ldap.forumsys.com' },
  userDn: 'uid=gauss,dc=example,dc=com',
  userPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
  usernameAttribute: 'uid',
  username: 'gauss',
  attributes: ['dn', 'sn', 'cn'],
})
```

#### User exists verification and return user details (without user's password)

```javascript
let authenticated = await authenticate({
  ldapOpts: { url: 'ldap://ldap.forumsys.com' },
  userDn: 'uid=gauss,dc=example,dc=com',
  verifyUserExists: true,
  userSearchBase: 'dc=example,dc=com',
  usernameAttribute: 'uid',
  username: 'gauss',
})
```

#### User authenticate and return user details with groups

```javascript
let authenticated = await authenticate({
  ldapOpts: { url: 'ldap://ldap.forumsys.com' },
  userDn: 'uid=gauss,dc=example,dc=com',
  userPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
  usernameAttribute: 'uid',
  username: 'gauss',
  groupsSearchBase: 'dc=example,dc=com',
  groupClass: 'groupOfUniqueNames',
  groupMemberAttribute: 'uniqueMember',
  // groupMemberUserAttribute: 'dn'
})
```

#### Fetch all users (admin search, without user passwords)

```javascript
const { fetchUsers } = require('ldap-authentication')

let users = await fetchUsers({
  ldapOpts: { url: 'ldap://ldap.forumsys.com' },
  adminDn: 'cn=read-only-admin,dc=example,dc=com',
  adminPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
  // userFilter: '(objectClass=person)',  // default: (|(uid=*)(sAMAccountName=*))
  // attributes: ['uid', 'sn', 'mail'],   // omitted = all attributes
  // pageSize: 500,                       // default: 1000
})
```

#### Complete example

The library works with both CommonJS and ES modules:

```javascript
import { authenticate } from 'ldap-authentication'
// or
const { authenticate } = require('ldap-authentication')
```

```javascript
const { authenticate } = require('ldap-authentication')

async function auth() {
  // auth with admin
  let options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
      // tlsOptions: { rejectUnauthorized: false }
    },
    adminDn: 'cn=read-only-admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'gauss',
    // starttls: false
  }

  let user = await authenticate(options)
  console.log(user)

  // auth with regular user
  options = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com',
      // tlsOptions: { rejectUnauthorized: false }
    },
    userDn: 'uid=einstein,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'einstein',
    // starttls: false
  }

  user = await authenticate(options)
  console.log(user)
}

auth()
```

### Example with StartTLS

```javascript
import { authenticate } from 'ldap-authentication'

async function auth() {
  // auth with admin
  let options = {
    ldapOpts: {
      url: 'ldap://ldap.example.com',
      tlsOptions: {
        rejectUnauthorized: false, // For self-signed certificates
        minVersion: 'TLSv1.2',
        servername: 'ldap.example.com' // For SNI (Server Name Indication)
      }
    },
    starttls: true, // Enable StartTLS
    adminDn: 'cn=admin,dc=example,dc=com',
    adminPassword: 'password',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'testuser'
  }

  let user = await authenticate(options)
  console.log(user)
}

auth()
```

**Important Notes for StartTLS:**
- Use `ldap://` URLs with `starttls: true` (not `ldaps://`)
- For `ldaps://` URLs, omit `starttls` and the connection will use TLS from the start
- TLS options like `rejectUnauthorized`, `minVersion`, and `servername` can be specified in `ldapOpts.tlsOptions`

#### Runnable examples

The [example/](example/) directory contains complete, runnable scripts: admin auth, self auth, group lookup,
`fetchUsers`, `verifyUserExists`, and StartTLS. They run against the bundled seeded test server
(start it via `docker compose up -d`, or point `LDAP_URL` at your own server):

```sh
docker compose up -d               # seeded OpenLDAP on localhost:1389 / 1636
node example/fetch-users.mjs       # or any other script in example/
docker compose down
```

## Parameters

- `ldapOpts`: This is passed to `ldapts` client directly
  - `url`: url of the ldap server. Example: `ldap://ldap.forumsys.com`
  - `tlsOptions`: options to pass to node tls. Example: `{ rejectUnauthorized: false }`
  - `connectTimeout`: Int. Default: `5000`. Connect timeout in ms
- `adminDn`: The DN of the admistrator. Example: `cn=read-only-admin,dc=example,dc=com`,
- `adminPassword`: The password of the admin.
- `userDn`: The DN of the user to be authenticated. This is only needed if `adminDn` and `adminPassword` are not provided.
  Example: `uid=gauss,dc=example,dc=com`
- `userPassword`: The password of the user
- `verifyUserExists` : if `true` user existence will be verified without password
- `userSearchBase`: The ldap base DN to search the user. Example: `dc=example,dc=com`
- `usernameAttribute`: The ldap search equality attribute name corresponding to the user's username.
  It will be used with the value in `username` to construct an ldap filter as `({attribute}={username})`
  to find the user and get user details in LDAP.
  In self authenticate mode (`userDn` and `userPassword` are provided, but not `adminDn` and `adminPassword`),
  if this value is not set, then authenticate will return true right after user bind succeed. No user details
  from LDAP search will be performed and returned.
  Example: `uid`
- `usernameFilter`: Prioritized alternative to usernameAttribute, allows you to provide a filter where `{{username}}` will 
  be replaced with the username provided
  Example: `(|(uid={{username}})(mail={{username}}))`
- `username`: The username to authenticate with. It is used together with the name in `usernameAttribute`
  to construct an ldap filter as `({attribute}={username})`
  to find the user and get user details in LDAP. Example: `some user input`
- `userFilter`: (used by `fetchUsers()`) The ldap search filter to select the users to return.
  By default it is `(|(uid=*)(sAMAccountName=*))`, which matches both POSIX (`uid`)
  and Active Directory (`sAMAccountName`) users. Example: `'(objectClass=person)'`,
  or `'(objectClass=*)'` to match everything
- `pageSize`: (used by `fetchUsers()`) The number of entries to fetch per page for the paged
  search. Default: `1000`
- `attributes`: A list of attributes of a user details to be returned from the LDAP server.
  If is set to `[]` or ommited, all details will be returned. Example: `['sn', 'cn']`
- `starttls`: Boolean. Use `STARTTLS` or not. When `true`, the connection will be upgraded to TLS
  using the STARTTLS extended operation. TLS options can be specified in `ldapOpts.tlsOptions`.
  Note: Use `starttls: true` with `ldap://` URLs, not `ldaps://` URLs
- `groupsSearchBase`: if specified with groupClass, will serve as search base for authenticated user groups
- `groupClass`: if specified with groupsSearchBase, will be used as objectClass in search filter for authenticated user groups
- `groupMemberAttribute`: if specified with groupClass and groupsSearchBase, will be used as member name (if not specified this defaults to `member`) in search filter for authenticated user groups
- `groupMemberUserAttribute`: if specified with groupClass and groupsSearchBase, will be used as the attribute on the user object (if not specified this defaults to `dn`) in search filter for authenticated user groups

### Which options for which mode?

| Mode (call) | Required | Commonly used in addition |
|---|---|---|
| Admin authenticate (`authenticate`) | `ldapOpts`, `adminDn`, `adminPassword`, `userPassword`, `userSearchBase`, `usernameAttribute` or `usernameFilter`, `username` | `attributes`, `groupsSearchBase`, `groupClass`, `starttls` |
| Self authenticate (`authenticate`) | `ldapOpts`, `userDn`, `userPassword` | `userSearchBase`, `usernameAttribute`, `attributes`, `groupsSearchBase`, `starttls` |
| Verify user exists (`authenticate` with `verifyUserExists: true`) | `ldapOpts`, `adminDn`, `adminPassword`, `userSearchBase`, `usernameAttribute` or `usernameFilter`, `username` | `attributes`, `groupsSearchBase`, `starttls` |
| Fetch all users (`fetchUsers`) | `ldapOpts`, `adminDn`, `adminPassword`, `userSearchBase` | `userFilter`, `attributes`, `pageSize`, `starttls` |

## Returns

The user object if `authenticate()` is success.

In version 4, a new function is added: `authenticateResult()`. It has the same call signature as `authenticate()` but returns an object `AuthenticationResult` with more details.

`fetchUsers()` returns an array of user objects, one per matched LDAP entry (each with its `dn` and the returned attributes), or an empty array if no user matches the filter.


### AuthenticationResult Object

AuthenticationResult object has the following fields:

- `code`: number. constants:
  - `AUTH_RESULT_FAILURE` = 0
  - `AUTH_RESULT_SUCCESS` = 1
  - `AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND` = -1
  - `AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS` = -2
  - `AUTH_RESULT_FAILURE_CREDENTIAL_INVALID` = -3
  - `AUTH_RESULT_FAILURE_UNCATEGORIZED` = -4
- `identity`: identity supplied as string
- `user`: user object if authentication is successful, otherwise null
- `message`: authentication message array, which contains server messages
- `client`: ldapClient instance

## Active Directory notes

- A typical admin bind DN is a service or admin account, e.g. `cn=Administrator,cn=users,dc=example,dc=com`,
  or a dedicated LDAP sync account.
- Username attributes: `sAMAccountName` for logins like `jdoe`, `userPrincipalName` for `jdoe@example.com`.
  To look a user up by either at once, use
  `usernameFilter: '(|(sAMAccountName={{username}})(userPrincipalName={{username}}))'`.
- Set `userSearchBase` to the OU containing the users (e.g. `ou=users,dc=example,dc=com`):
  the search is faster and avoids `AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS`.
- `fetchUsers()` uses LDAP paged results, so Active Directory's usual 1000-entry limit per search
  is not an issue (adjust the page size with `pageSize` if needed).
- Binary attributes such as `thumbnailPhoto` should be requested as `thumbnailPhoto;binary`;
  they are returned as base64-encoded strings.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ECONNREFUSED`, `ETIMEDOUT`, or other connect errors | `ldapOpts.url` is wrong or the server is unreachable. Check the URL, the network/firewall, and `connectTimeout`. |
| `LdapAuthenticationError` with `admin bind failed` / `user bind failed` | Wrong `adminDn`/`adminPassword`, or `userDn`/`userPassword` in self mode. Verify the bind manually, e.g. `ldapsearch -b dc=example,dc=com -D <dn> -w <password> dn`. |
| `identity not found` (`AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND`) | The user does not exist under `userSearchBase`, or `usernameAttribute`/`username`/`usernameFilter` does not match the attribute(s) stored on the server. |
| `identity ambiguous` (`AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS`) | The search matched multiple entries - narrow `userSearchBase` or make the filter more specific. |
| `Invalid credentials` (`AUTH_RESULT_FAILURE_CREDENTIAL_INVALID`) | The user was found but the password is wrong. |
| TLS certificate errors | For self-signed certificates use `tlsOptions: { rejectUnauthorized: false }`; add `servername` for SNI. Use `ldaps://` (without `starttls`) or `ldap://` with `starttls: true`. |

## Old Stuff

In version 2, The user object has a `raw` field that has the raw data from the LDAP/AD server. It can be used to access buffer objects (profile pics for example).

Buffer data can now be accessed by `user.raw.profilePhoto`, etc, instead of `user.profilePhoto`.

In version 3, the `raw` field is no longer used. Instead, append `;binary` to the attributes you
want to get back as base64-encoded string. Check the following example on how to get a user's profile photo:

```javascript
export async function verifyLogin(email: string, password: string) {

  const options = {
   //...other config options
    userPassword: password,
    username: email,
    attributes: ['thumbnailPhoto;binary', 'givenName', 'sn', 'sAMAccountName', 'userPrincipalName', 'memberOf' ]
  };

  try {
    const ldapUser = await authenticate(options);

    if (!ldapUser) {
      return { error: "user not found" };
    }

    // accessing the image
    const profilePhoto = ldapUser['thumbnailPhoto;binary'];

    /* using the image
 <img src={`data:image/*;base64,${profilePhoto}`} />
    */
    return { user: ldapUser };
  }
}
```

## Supported Node Versions

Version 2 supports Node version 12, 14, 15, 16, 17 and 18.

Version 3 supports Node version 16, 17, 18, 20 and 22.

Version 4 supports Node version 22 and above.
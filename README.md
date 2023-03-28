# A Simple node Library that Authenticates a User Against an LDAP/AD Server

[![Integration Tests](https://github.com/shaozi/ldap-authentication/actions/workflows/integration-test.yml/badge.svg)](https://github.com/shaozi/ldap-authentication/actions/workflows/integration-test.yml)
[![Known Vulnerabilities](https://snyk.io/test/github/shaozi/ldap-authentication/badge.svg?targetFile=package.json)](https://snyk.io/test/github/shaozi/ldap-authentication?targetFile=package.json)

## Goal

Make authentication with an LDAP server easy.

## Description

This library use `ldapjs` as the underneath library. It has three modes of authentications:

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

#### Complete example

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

## Parameters

- `ldapOpts`: This is passed to `ldapjs` client directly
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
- `username`: The username to authenticate with. It is used together with the name in `usernameAttribute`
  to construct an ldap filter as `({attribute}={username})`
  to find the user and get user details in LDAP. Example: `some user input`
- `attributes`: A list of attributes of a user details to be returned from the LDAP server.
  If is set to `[]` or ommited, all details will be returned. Example: `['sn', 'cn']`
- `starttls`: Boolean. Use `STARTTLS` or not
- `groupsSearchBase`: if specified with groupClass, will serve as search base for authenticated user groups
- `groupClass`: if specified with groupsSearchBase, will be used as objectClass in search filter for authenticated user groups
- `groupMemberAttribute`: if specified with groupClass and groupsSearchBase, will be used as member name (if not specified this defaults to `member`) in search filter for authenticated user groups
- `groupMemberUserAttribute`: if specified with groupClass and groupsSearchBase, will be used as the attribute on the user object (if not specified this defaults to `dn`) in search filter for authenticated user groups

## Returns

The user object if `authenticate()` is success.

In version 2, The user object has a `raw` field that has the raw data from the LDAP/AD server. It can be used to access buffer objects (profile pics for example).

Buffer data can now be accessed by `user.raw.profilePhoto`, etc, instead of `user.profilePhoto`.

In version 3, the `raw` field is no longer used. Instead, append `;binary` to the attributes you
want to get back as buffer. Check the following example on how to get a user's profile photo:

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
	<img src={`data:image/*;base64,${user.profilePhoto}`} />
    */
    return { user: ldapUser };
  }
}
```

## Supported Node Versions

Version 2 supports Node version 12, 14, 15, 16, 17 and 18.

Version 3 supports Node version 15, 16, 17 and 18

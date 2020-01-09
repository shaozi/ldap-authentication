# A Simple node Library that Authenticates a User Against an LDAP/AD Server

This library use `ldapjs` as the underneath library. It has two modes of authentications:

1. **Admin authenticate mode**. If an admin user is provided, the library will login (ldap bind) with the admin user,
   then search for the user to be authenticated, get its DN (distinguish name), then use
   the user DN and password to login again. If every thing is ok, the user details will
   be returned.

2. **Self authenticate mode**. If the admin user is not provided, then the `userDn` and `userPassword` must be provided.
   If any of `userSearchBase` or `usernameAttribute` is missing, then the lib simply does a login with
   the `userDn` and `userPassword` (ldap bind), and returns true if succeeds.

   Otherwise, the lib does a login with the `userDn` and `userPassword` (ldap bind),
   then does a search on the user and return the user's details.

## Features

* Can use an admin to search and authenticate a user
* Can also use a regular user and authenticate the user itself
* Supports ldap, ldaps, and STARTTLS
* Async/Await Promise

## How to Use

### Installation

```sh
npm install ldap-authentication --save
```

### Examples

An example on how to use with Passport is [passport-ldap-example](https://github.com/shaozi/passport-ldap-example).

#### User authenticate without getting user details

```javascript
let authenticated = await authenticate({
  ldapOptions: {url: 'ldap://ldap.forumsys.com'},
  userDn: 'uid=gauss,dc=example,dc=com',
  userPassword: 'password'
})
```

#### User authenticate and return user details

```javascript
let authenticated = await authenticate({
  ldapOptions: {url: 'ldap://ldap.forumsys.com'},
  userDn: 'uid=gauss,dc=example,dc=com',
  userPassword: 'password',
  userSearchBase: 'dc=example,dc=com',
  usernameAttribute: 'uid',
  username: 'gauss'
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
    username: 'gauss'
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
    username: 'einstein'
    // starttls: false
  }

  user = await authenticate(options)
  console.log(user)
}

auth()

```

## Parameters

* `ldapOpts`: This is passed to `ldapjs` client directly
  * `url`: url of the ldap server. Example: `ldap://ldap.forumsys.com`
  * `tlsOptions`: options to pass to node tls. Example: `{ rejectUnauthorized: false }`
* `adminDn`: The DN of the admistrator. Example: 'cn=read-only-admin,dc=example,dc=com',
* `adminPassword`: The password of the admin.
* `userDn`: The DN of the user to be authenticated. This is only needed if `adminDn` and `adminPassword` are not provided.
            Example: `uid=gauss,dc=example,dc=com`
* `userPassword`: The password of the user,
* `userSearchBase`: The ldap base DN to search the user. Example: `dc=example,dc=com`
* `usernameAttribute`: The ldap search equality attribute name corresponding to the user's username.
                       It will be used with the value in `username` to construct an ldap filter as `({attribute}={username})`
                       to find the user and get user details in LDAP.
                       In self authenticate mode (`userDn` and `userPassword` are provided, but not `adminDn` and `adminPassword`),
                       if this value is not set, then authenticate will return true right after user bind succeed. No user details
                       from LDAP search will be performed and returned.
                       Example: `uid`
* `username`: The username to authenticate with. It is used together with the name in `usernameAttribute` 
              to construct an ldap filter as `({attribute}={username})`
              to find the user and get user details in LDAP. Example: `some user input`
* `starttls`: Boolean. Use `STARTTLS` or not

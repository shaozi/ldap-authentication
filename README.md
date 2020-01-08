# A Simple node Library that Authenticates a User Against an LDAP/AD Server

This library use `ldapjs` as the underneath library. It has two modes of authentications:

1. If an admin user is provided, the library will login (ldap bind) with the admin user,
   then search for the user to be authenticated, get its DN (distinguish name), then use
   the user DN and password to login again. If every thing is ok, the user details will
   be returned.

2. If the admin user is not provided, then the user DN must be provided.
   The lib simply does a login with the user DN and password, then do a search on
   the user and return the user's details.

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

### Simple example

```javascript
let user = await authenticate(options)
```

### Complete example

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
    userSearchFilter: '(uid=gauss)',
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
    userSearchFilter: '(uid=einstein)',
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
* `userDn`: The DN of the user to be authenticated. This is only needed if `adminDn` and `adminPassword` are not provided. Example: `uid=gauss,dc=example,dc=com`
* `userPassword`: The password of the user,
* `userSearchBase`: The ldap base DN to search the user. Example: `dc=example,dc=com`
* `userSearchFilter`: The ldap search string to get user's detail information. Example: `(uid=gauss)`'
* `starttls`: Boolean. Use `STARTTLS` or not

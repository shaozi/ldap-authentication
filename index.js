const assert = require('assert')
const ldap = require('ldapjs')

// bind and return the ldap client
function _ldapBind(dn, password, starttls, ldapOpts) {
  return new Promise(function (resolve, reject) {
    ldapOpts.connectTimeout = ldapOpts.connectTimeout || 5000
    var client = ldap.createClient(ldapOpts)
    if (starttls) {
      client.starttls(ldapOpts.tlsOptions, null, function (error) {
        if (error) {
          reject(error)
          return
        }
        client.bind(dn, password, function (err) {
          if (err) {
            reject(err)
            client.unbind()
            return
          }
          ldapOpts.log && ldapOpts.log.trace('bind success!')
          resolve(client)
        })
      })
    } else {
      client.bind(dn, password, function (err) {
        if (err) {
          reject(err)
          client.unbind()
          return
        }
        ldapOpts.log && ldapOpts.log.trace('bind success!')
        resolve(client)
      })
    }
  })
}

// search a user and return the object
async function _searchUser(
  ldapClient,
  searchBase,
  usernameAttribute,
  username
) {
  return new Promise(function (resolve, reject) {
    var filter = new ldap.filters.EqualityFilter({
      attribute: usernameAttribute,
      value: username,
    })
    ldapClient.search(
      searchBase,
      {
        filter: filter,
        scope: 'sub',
      },
      function (err, res) {
        var user = null
        if (err) {
          reject(err)
          ldapClient.unbind()
          return
        }
        res.on('searchEntry', function (entry) {
          user = entry.object
        })
        res.on('searchReference', function (referral) {
          console.log('referral: ' + referral.uris.join())
        })
        res.on('error', function (err) {
          reject(err)
          ldapClient.unbind()
        })
        res.on('end', function (result) {
          if (result.status != 0) {
            reject(new Error('ldap search status is not 0, search failed'))
          } else {
            resolve(user)
          }
          ldapClient.unbind()
        })
      }
    )
  })
}

// search a groups which user is member
async function _searchUserGroups(ldapClient, searchBase, user, groupClass) {
  return new Promise(function (resolve, reject) {
    ldapClient.search(
      searchBase,
      {
        filter: `(&(objectclass=${groupClass})(member=${user.dn}))`,
        scope: 'sub',
      },
      function (err, res) {
        var groups = []
        if (err) {
          reject(err)
          ldapClient.unbind()
          return
        }
        res.on('searchEntry', function (entry) {
          groups.push(entry.object)
        })
        res.on('searchReference', function (referral) {
          console.log('referral: ' + referral.uris.join())
        })
        res.on('error', function (err) {
          reject(err)
          ldapClient.unbind()
        })
        res.on('end', function (result) {
          if (result.status != 0) {
            reject(new Error('ldap search status is not 0, search failed'))
          } else {
            resolve(groups)
          }
          ldapClient.unbind()
        })
      }
    )
  })
}

async function authenticateWithAdmin(
  adminDn,
  adminPassword,
  userSearchBase,
  usernameAttribute,
  username,
  userPassword,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass
) {
  var ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(
      adminDn,
      adminPassword,
      starttls,
      ldapOpts
    )
  } catch (error) {
    throw { admin: error }
  }
  var user = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username
  )
  ldapAdminClient.unbind()
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    throw new LdapAuthenticationError(
      'user not found or usernameAttribute is wrong'
    )
  }
  var userDn = user.dn
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    throw error
  }
  ldapUserClient.unbind()
  if (groupsSearchBase && groupClass) {
    try {
      ldapAdminClient = await _ldapBind(
        adminDn,
        adminPassword,
        starttls,
        ldapOpts
      )
    } catch (error) {
      throw error
    }
    var groups = await _searchUserGroups(
      ldapAdminClient,
      groupsSearchBase,
      user,
      groupClass
    )
    user.groups = groups
    ldapAdminClient.unbind()
  }
  return user
}

async function authenticateWithUser(
  userDn,
  userSearchBase,
  usernameAttribute,
  username,
  userPassword,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass
) {
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    throw error
  }
  if (!usernameAttribute || !userSearchBase) {
    // if usernameAttribute is not provided, no user detail is needed.
    ldapUserClient.unbind()
    return true
  }
  var user = await _searchUser(
    ldapUserClient,
    userSearchBase,
    usernameAttribute,
    username
  )
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `user logged in, but user details could not be found. (${usernameAttribute}=${username}). Probabaly wrong attribute or searchBase?`
      )
    throw new LdapAuthenticationError(
      'user logged in, but user details could not be found. Probabaly usernameAttribute or userSearchBase is wrong?'
    )
  }
  ldapUserClient.unbind()
  if (groupsSearchBase && groupClass) {
    try {
      ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
    } catch (error) {
      throw error
    }
    var groups = await _searchUserGroups(
      ldapUserClient,
      groupsSearchBase,
      user,
      groupClass
    )
    user.groups = groups
    ldapUserClient.unbind()
  }
  return user
}

async function authenticate(options) {
  if (!options.userDn) {
    assert(options.adminDn, 'Admin mode adminDn must be provided')
    assert(options.adminPassword, 'Admin mode adminPassword must be provided')
    assert(options.userSearchBase, 'Admin mode userSearchBase must be provided')
    assert(
      options.usernameAttribute,
      'Admin mode usernameAttribute must be provided'
    )
    assert(options.username, 'Admin mode username must be provided')
  } else {
    assert(options.userDn, 'User mode userDn must be provided')
  }
  assert(options.userPassword, 'userPassword must be provided')
  assert(
    options.ldapOpts && options.ldapOpts.url,
    'ldapOpts.url must be provided'
  )
  if (options.adminDn) {
    assert(
      options.adminPassword,
      'adminDn and adminPassword must be both provided.'
    )
    return await authenticateWithAdmin(
      options.adminDn,
      options.adminPassword,
      options.userSearchBase,
      options.usernameAttribute,
      options.username,
      options.userPassword,
      options.starttls,
      options.ldapOpts,
      options.groupsSearchBase,
      options.groupClass
    )
  }
  assert(options.userDn, 'adminDn/adminPassword OR userDn must be provided')
  return await authenticateWithUser(
    options.userDn,
    options.userSearchBase,
    options.usernameAttribute,
    options.username,
    options.userPassword,
    options.starttls,
    options.ldapOpts,
    options.groupsSearchBase,
    options.groupClass
  )
}

class LdapAuthenticationError extends Error {
  constructor(message) {
    super(message)
    // Ensure the name of this error is the same as the class name
    this.name = this.constructor.name
    // This clips the constructor invocation from the stack trace.
    // It's not absolutely essential, but it does make the stack trace a little nicer.
    //  @see Node.js reference (bottom)
    Error.captureStackTrace(this, this.constructor)
  }
}

module.exports.authenticate = authenticate
module.exports.LdapAuthenticationError = LdapAuthenticationError

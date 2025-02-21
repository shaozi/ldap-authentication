const assert = require('assert')
const ldapts = require('ldapts')
// escape the , in CN in DN
function _ldapEscapeDN(s) {
  let ret = ''
  let comaPositions = []
  let done = false
  let countEq = 0
  for (let i = 0; !done && i < s.length; i++) {
    switch (s[i]) {
      case '\\':
        // user already escapped, continue
        i++
        break
      case ',':
        if (countEq == 1) {
          comaPositions.push(i)
        }
        break
      case '=':
        countEq++
        if (countEq == 2) {
          done = true
        }
        break
    }
  }
  if (done) {
    comaPositions.pop()
  }
  let lastIndex = 0
  for (let i of comaPositions) {
    ret += s.substring(lastIndex, i)
    ret += '\\,'
    lastIndex = i + 1
  }
  ret += s.substring(lastIndex)
  return ret
}

// bind and return the ldap client
async function _ldapBind(dn, password, starttls, ldapOpts) {
  // TODO: check if ldapts expects escaped dn or not (possible double escaping problems?)
  dn = _ldapEscapeDN(dn)
  ldapOpts.connectTimeout = ldapOpts.connectTimeout || 5000
  let client = new ldapts.Client(ldapOpts)

  if (starttls) {
    await client.startTLS(ldapOpts.tlsOptions)
  }

  await client.bind(dn, password)
  ldapOpts.log && ldapOpts.log.trace('bind success!')
  return client
}

// search a user and return the object
async function _searchUser(
  ldapClient,
  searchBase,
  usernameAttribute,
  username,
  attributes = null
) {
  let filter = new ldapts.EqualityFilter({
    attribute: usernameAttribute,
    value: username,
  })
  let searchOptions = {
    filter: filter,
    scope: 'sub',
    attributes: attributes,
  }
  if (attributes) {
    searchOptions.attributes = attributes
  }

  // TODO: we don't support reference yet
  // If the server was able to locate the entry referred to by the baseObject
  // but could not search one or more non-local entries,
  // the server may return one or more SearchResultReference messages,
  // each containing a reference to another set of servers for continuing the operation.
  // referral.uris
  const { searchEntries, searchReferences } = await ldapClient.search(
    searchBase,
    searchOptions
  )

  let user
  if (
    !searchEntries ||
    searchEntries.length < 1 ||
    !searchEntries[0] ||
    !searchEntries[0].dn
  ) {
    user = null
  } else {
    user = searchEntries[0]
  }

  return user
}

// search a groups which user is member
async function _searchUserGroups(
  ldapClient,
  searchBase,
  user,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn'
) {
  // Below works, but prefer using ldapts Filter subclasses to build this search, so that correct escaping is done
  // const filter = `(&(objectclass=${groupClass})(${groupMemberAttribute}=${user[groupMemberUserAttribute]}))`
  const filter = new ldapts.AndFilter({
    filters: [
      new ldapts.EqualityFilter({
        attribute: 'objectclass',
        value: groupClass,
      }),
      new ldapts.EqualityFilter({
        attribute: groupMemberAttribute,
        value: user[groupMemberUserAttribute],
      }),
    ],
  })

  const { searchEntries, searchReferences } = await ldapClient.search(
    searchBase,
    {
      filter: filter,
      scope: 'sub',
    }
  )

  let groups
  if (!searchEntries || searchEntries.length < 1) {
    groups = []
  } else {
    groups = searchEntries
  }
  // ldapjs has group.objectName, ldapts does not have it. instead, use dn
  // add objectName back for backward compatibility
  for (let group of groups) {
    if (typeof group.objectName === 'undefined') {
      group.objectName = group.dn
    }
  }
  return groups
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
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  let ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(
      adminDn,
      adminPassword,
      starttls,
      ldapOpts
    )
  } catch (error) {
    if (ldapAdminClient && ldapAdminClient.isConnected) {
      await ldapAdminClient.unbind()
    }
    throw new LdapAuthenticationError(error)
  }
  let user = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    await ldapAdminClient.unbind()
    throw new LdapAuthenticationError(
      'user not found or usernameAttribute is wrong'
    )
  }
  let userDn = user.dn
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    if (ldapUserClient && ldapUserClient.isConnected) {
      await ldapUserClient.unbind()
    }
    throw new LdapAuthenticationError(error)
  }
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    let groups = await _searchUserGroups(
      ldapAdminClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
  }
  await ldapAdminClient.unbind()
  await ldapUserClient.unbind()
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
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    if (ldapUserClient && ldapUserClient.isConnected) {
      await ldapUserClient.unbind()
    }
    throw new LdapAuthenticationError(error)
  }
  if (!usernameAttribute || !userSearchBase) {
    // if usernameAttribute is not provided, no user detail is needed.
    await ldapUserClient.unbind()
    return true
  }
  let user = await _searchUser(
    ldapUserClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `user logged in, but user details could not be found. (${usernameAttribute}=${username}). Probabaly wrong attribute or searchBase?`
      )
    await ldapUserClient.unbind()
    throw new LdapAuthenticationError(
      'user logged in, but user details could not be found. Probabaly usernameAttribute or userSearchBase is wrong?'
    )
  }
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    let groups = await _searchUserGroups(
      ldapUserClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
  }
  await ldapUserClient.unbind()
  return user
}

async function verifyUserExists(
  adminDn,
  adminPassword,
  userSearchBase,
  usernameAttribute,
  username,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  let ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(
      adminDn,
      adminPassword,
      starttls,
      ldapOpts
    )
  } catch (error) {
    if (ldapAdminClient && ldapAdminClient.isConnected) {
      await ldapAdminClient.unbind()
    }
    throw new LdapAuthenticationError(error)
  }
  let user = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    await ldapAdminClient.unbind()
    throw new LdapAuthenticationError(
      'user not found or usernameAttribute is wrong'
    )
  }
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    let groups = await _searchUserGroups(
      ldapAdminClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
  }
  await ldapAdminClient.unbind()
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
  assert(
    options.ldapOpts && options.ldapOpts.url,
    'ldapOpts.url must be provided'
  )
  if (options.verifyUserExists) {
    assert(options.adminDn, 'Admin mode adminDn must be provided')
    assert(
      options.adminPassword,
      'adminDn and adminPassword must be both provided.'
    )
    return await verifyUserExists(
      options.adminDn,
      options.adminPassword,
      options.userSearchBase,
      options.usernameAttribute,
      options.username,
      options.starttls,
      options.ldapOpts,
      options.groupsSearchBase,
      options.groupClass,
      options.groupMemberAttribute,
      options.groupMemberUserAttribute,
      options.attributes
    )
  }
  assert(options.userPassword, 'userPassword must be provided')
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
      options.groupClass,
      options.groupMemberAttribute,
      options.groupMemberUserAttribute,
      options.attributes
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
    options.groupClass,
    options.groupMemberAttribute,
    options.groupMemberUserAttribute,
    options.attributes
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

module.exports.exportForTesting = {
  _ldapEscapeDN,
}

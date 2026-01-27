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

const AUTH_RESULT_FAILURE = 0
const AUTH_RESULT_SUCCESS = 1
const AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = -1
const AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = -2
const AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = -3
const AUTH_RESULT_FAILURE_UNCATEGORIZED = -4

class AuthenticationResult {
  #authCode = AUTH_RESULT_FAILURE_UNCATEGORIZED
  #identity
  #user
  #messages = []
  #client

  constructor(authCode, identity, user, messages, client) {
    this.#authCode = authCode // one of the above constants
    this.#identity = identity // identity supplied as string
    this.#user     = user // user object found on ldap server OR null
    this.#messages = messages // authentication messages array, which contains server messages
    this.#client   = client // ldapClient instance
  }

  get code() {
    return this.#authCode
  }

  get identity() {
    return this.#identity
  }

  get messages() {
    return this.#messages
  }

  get client() {
    return this.#client
  }

  get user() {
    return this.#user
  }
}

const authenticationMessages = {
  AUTH_RESULT_FAILURE: 'Authentication failed',
  AUTH_RESULT_SUCCESS: 'Authentication successful',
  AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND: 'Authentication identity not found',
  AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS: 'Authentication identity ambiguous',
  AUTH_RESULT_FAILURE_CREDENTIAL_INVALID: 'Invalid credentials',
  AUTH_RESULT_FAILURE_UNCATEGORIZED: 'Uncategorized authentication failure',
}

// bind and return the ldap client
async function _ldapBind(dn, password, starttls, ldapOpts) {
  // TODO: check if ldapts expects escaped dn or not (possible double escaping problems?)
  dn = _ldapEscapeDN(dn)
  ldapOpts.connectTimeout = ldapOpts.connectTimeout || 5000

  // When using StartTLS, we need to exclude tlsOptions from the Client constructor
  // and only pass them to the startTLS() method to avoid connection conflicts.
  // According to ldapts documentation:
  // - For LDAPS (ldaps://): pass tlsOptions to Client constructor
  // - For StartTLS (ldap://): do NOT pass tlsOptions to Client constructor, only to startTLS()
  // - For plain LDAP (ldap://): do NOT pass tlsOptions to Client constructor
  let clientOpts = ldapOpts
  const isLdaps = ldapOpts.url && ldapOpts.url.startsWith('ldaps://')

  // Only pass tlsOptions to Client constructor if using ldaps:// protocol
  // For ldap:// protocol (plain or StartTLS), exclude tlsOptions from constructor
  if (!isLdaps && ldapOpts.tlsOptions) {
    // Create a shallow copy of ldapOpts without tlsOptions for the Client constructor
    const { tlsOptions, ...optsWithoutTls } = ldapOpts
    clientOpts = optsWithoutTls
  }

  let client = new ldapts.Client(clientOpts)

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
  attributes = null,
  explicitBufferAttributes = null
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
  if(explicitBufferAttributes) {
    searchOptions.explicitBufferAttributes = explicitBufferAttributes
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
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND],
      ldapClient
    )
  } else {
    if (searchEntries.length > 1) {
      return new AuthenticationResult(
        AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
        username,
        null,
        [authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS],
        ldapClient
      )
    }

    user = searchEntries[0]
  }

  // when attribute endwith ;binary, ldapts returns Buffer, we convert them into base64 string
  if (user != null && attributes != null) {
    for (let attr of attributes) {
      if (attr.endsWith(';binary') && Buffer.isBuffer(user[attr])) {
        user[attr] = user[attr].toString('base64')
      }
    }
  }
  // when attribute is one of the explicitBufferAttributes, should convert to base64 string
  if (user != null && explicitBufferAttributes != null) {
    for (let attr of explicitBufferAttributes) {
      if (Buffer.isBuffer(user[attr])) {
        user[attr] = user[attr].toString('base64')
      }
    }
  }

  return new AuthenticationResult(
    AUTH_RESULT_SUCCESS,
    username,
    user,
    [authenticationMessages.AUTH_RESULT_SUCCESS],
    ldapClient
  )
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
  attributes = null,
  explicitBufferAttributes = null
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

    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'admin bind failed'],
      ldapAdminClient
    )
  }

  let searchResult = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes,
    explicitBufferAttributes
  )

  let user = searchResult.user

  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    await ldapAdminClient.unbind()
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND],
      ldapAdminClient
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

    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE_CREDENTIAL_INVALID, error.message || 'invalid credentials'],
      ldapAdminClient
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
  await ldapUserClient.unbind()

  return new AuthenticationResult(
    AUTH_RESULT_SUCCESS,
    username,
    user,
    [authenticationMessages.AUTH_RESULT_SUCCESS],
    ldapAdminClient
  )
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
  attributes = null,
  explicitBufferAttributes = null
) {
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    if (ldapUserClient && ldapUserClient.isConnected) {
      await ldapUserClient.unbind()
    }

    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'user bind failed'],
      ldapUserClient
    )
  }
  if (!usernameAttribute || !userSearchBase) {
    // if usernameAttribute is not provided, no user detail is needed.
    await ldapUserClient.unbind()
    return new AuthenticationResult(
      AUTH_RESULT_SUCCESS,
      username,
      {},
      [authenticationMessages.AUTH_RESULT_SUCCESS],
      ldapUserClient
    )
  }

  let searchResult = await _searchUser(
    ldapUserClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes,
    explicitBufferAttributes
  )

  let user = searchResult.user

  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `user logged in, but user details could not be found. (${usernameAttribute}=${username}). Probabaly wrong attribute or searchBase?`
      )
    await ldapUserClient.unbind()

    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [
        authenticationMessages.AUTH_RESULT_FAILURE,
        'user logged in, but user details could not be found. Probabaly usernameAttribute or userSearchBase is wrong?',
      ],
      ldapUserClient
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

  return new AuthenticationResult(
    AUTH_RESULT_SUCCESS,
    username,
    user,
    [authenticationMessages.AUTH_RESULT_SUCCESS],
    ldapUserClient
  )
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
  attributes = null,
  explicitBufferAttributes = null
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
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'admin bind failed'],
      ldapAdminClient
    )
  }

  let searchResult = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes,
    explicitBufferAttributes
  )

  let user = searchResult.user

  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    await ldapAdminClient.unbind()
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
      username,
      null,
      [
        authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
        'user not found or usernameAttribute is wrong'
      ],
      ldapAdminClient
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
  return new AuthenticationResult(
    AUTH_RESULT_SUCCESS,
    username,
    user,
    [authenticationMessages.AUTH_RESULT_SUCCESS],
    ldapAdminClient
  )
}

async function authenticate(options) {
  const result = await authenticateResult(options)

  if (result.code !== AUTH_RESULT_SUCCESS) {
    throw new LdapAuthenticationError(
      result.messages[result.messages.length - 1]
    )
  }

  return result.user
}

async function authenticateResult(options) {
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
      options.attributes,
      options.explicitBufferAttributes
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
      options.attributes,
      options.explicitBufferAttributes
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
    options.attributes,
    options.explicitBufferAttributes
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

module.exports.AUTH_RESULT_FAILURE = AUTH_RESULT_FAILURE
module.exports.AUTH_RESULT_SUCCESS = AUTH_RESULT_SUCCESS
module.exports.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND =
  AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND
module.exports.AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS =
  AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS
module.exports.AUTH_RESULT_FAILURE_CREDENTIAL_INVALID =
  AUTH_RESULT_FAILURE_CREDENTIAL_INVALID
module.exports.AUTH_RESULT_FAILURE_UNCATEGORIZED =
  AUTH_RESULT_FAILURE_UNCATEGORIZED

module.exports.AuthenticationResult = AuthenticationResult

module.exports.authenticate = authenticate
module.exports.authenticateResult = authenticateResult
module.exports.LdapAuthenticationError = LdapAuthenticationError

module.exports.exportForTesting = {
  _ldapEscapeDN,
}

const ldapts = require('ldapts')

// escape the , in the value of the first RDN of a DN
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

const DEFAULT_FETCH_USERS_FILTER = '(|(uid=*)(sAMAccountName=*))'
const DEFAULT_FETCH_USERS_PAGE_SIZE = 1000

/**
 * Thrown by authenticate()/authenticateResult()/fetchUsers() on failure.
 * `message` describes the failure; `code` (when set) is one of the
 * AUTH_RESULT_* constants, mirroring the outcome that authenticateResult()
 * reports for the same failure. Missing required options also throw this
 * error, with all the missing fields listed in `message`.
 */
class LdapAuthenticationError extends Error {
  constructor(message, code) {
    super(message)
    // Ensure the name of this error is the same as the class name
    this.name = this.constructor.name
    if (code !== undefined) {
      this.code = code
    }
    // This clips the constructor invocation from the stack trace.
    // It's not absolutely essential, but it does make the stack trace a little nicer.
    Error.captureStackTrace(this, this.constructor)
  }
}

/**
 * Result object returned by {@link authenticateResult}. Inspect `code` (one
 * of the AUTH_RESULT_* constants) and `messages` to classify failures.
 */
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

// bind with (dn, password) and return the connected ldap client.
// If the connection or the bind fails, the client is unbound again before
// the error is rethrown, so callers never leak a connected socket.
async function _ldapBind(dn, password, { starttls, ldapOpts }) {
  // ldapts passes a string DN through to the server as-is (no escaping is
  // done by ldapts), so the value of the first RDN is escaped here (a DN
  // like `cn=Doe, John,ou=users,...` would otherwise be parsed by the server
  // as three RDNs instead of one)
  dn = _ldapEscapeDN(dn)
  const opts = { ...ldapOpts }
  opts.connectTimeout = ldapOpts.connectTimeout || 5000

  // When using StartTLS, we need to exclude tlsOptions from the Client constructor
  // and only pass them to the startTLS() method to avoid connection conflicts.
  // According to ldapts documentation:
  // - For LDAPS (ldaps://): pass tlsOptions to Client constructor
  // - For StartTLS (ldap://): do NOT pass tlsOptions to Client constructor, only to startTLS()
  // - For plain LDAP (ldap://): do NOT pass tlsOptions to Client constructor
  const isLdaps = opts.url && opts.url.startsWith('ldaps://')
  if (!isLdaps) {
    delete opts.tlsOptions
  }

  const client = new ldapts.Client(opts)
  try {
    if (starttls) {
      await client.startTLS(ldapOpts.tlsOptions)
    }
    await client.bind(dn, password)
  } catch (error) {
    if (client.isConnected) {
      try {
        await client.unbind()
      } catch (unbindError) {
        // the socket was probably already closed; nothing else to do
      }
    }
    throw error
  }
  ldapOpts.log && ldapOpts.log.trace('bind success!')
  return client
}

// convert attribute values that ldapts returned as Buffer (attributes with
// a `;binary` suffix, or the ones listed in explicitBufferAttributes) into
// base64 strings
function _toBase64Attributes(user, attributes, explicitBufferAttributes) {
  if (user == null) {
    return
  }
  // when attribute endwith ;binary, ldapts returns Buffer, we convert them into base64 string
  if (attributes != null) {
    for (let attr of attributes) {
      if (attr.endsWith(';binary') && Buffer.isBuffer(user[attr])) {
        user[attr] = user[attr].toString('base64')
      }
    }
  }
  // when attribute is one of the explicitBufferAttributes, should convert to base64 string
  if (explicitBufferAttributes != null) {
    for (let attr of explicitBufferAttributes) {
      if (Buffer.isBuffer(user[attr])) {
        user[attr] = user[attr].toString('base64')
      }
    }
  }
}

// search a user and return the object
async function _searchUser(client, options) {
  const {
    userSearchBase,
    usernameFilter,
    usernameAttribute,
    username,
    attributes = null,
    explicitBufferAttributes = null,
  } = options

  let filter
  if (usernameFilter) {
    // replace `{{username}}` with the RFC 2254-escaped username, so LDAP
    // filter metacharacters inside the username cannot change the structure
    // of the filter
    filter = usernameFilter.replaceAll('{{username}}', ldapts.Filter.escape(username))
  } else {
    filter = new ldapts.EqualityFilter({
      attribute: usernameAttribute,
      value: username,
    })
  }

  let searchOptions = {
    filter: filter,
    scope: 'sub',
  }
  if (attributes) {
    searchOptions.attributes = attributes
  }
  if (explicitBufferAttributes) {
    searchOptions.explicitBufferAttributes = explicitBufferAttributes
  }

  // TODO: we don't support reference yet
  const { searchEntries } = await client.search(userSearchBase, searchOptions)

  let user
  if (
    !searchEntries ||
    searchEntries.length < 1 ||
    !searchEntries[0] ||
    !searchEntries[0].dn
  ) {
    user = null
  } else if (searchEntries.length > 1) {
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS],
      client
    )
  } else {
    user = searchEntries[0]
  }

  if (!user) {
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND],
      client
    )
  }

  _toBase64Attributes(user, attributes, explicitBufferAttributes)
  return new AuthenticationResult(
    AUTH_RESULT_SUCCESS,
    username,
    user,
    [authenticationMessages.AUTH_RESULT_SUCCESS],
    client
  )
}

// search the groups which user is member and attach them to user.groups;
// does nothing when group lookup is not configured
async function _attachGroups(client, user, options) {
  const {
    groupsSearchBase,
    groupClass,
    groupMemberAttribute = 'member',
    groupMemberUserAttribute = 'dn',
  } = options
  if (!groupsSearchBase || !groupClass || !groupMemberAttribute) {
    return
  }

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

  const { searchEntries } = await client.search(groupsSearchBase, {
    filter: filter,
    scope: 'sub',
  })

  let groups = searchEntries || []
  // ldapjs has group.objectName, ldapts does not have it. instead, use dn
  // add objectName back for backward compatibility
  for (let group of groups) {
    if (typeof group.objectName === 'undefined') {
      group.objectName = group.dn
    }
  }
  user.groups = groups
}

// search all users under the search base and return the list of user objects
async function _fetchAllUsers(client, options) {
  const {
    userSearchBase,
    userFilter,
    attributes = null,
    explicitBufferAttributes = null,
    pageSize = DEFAULT_FETCH_USERS_PAGE_SIZE,
  } = options

  let searchOptions = {
    filter: userFilter || DEFAULT_FETCH_USERS_FILTER,
    scope: 'sub',
    // always use paged results, so more than the usual server-side limit
    // (usually 1000 entries per page) can be returned
    paged: { pageSize: pageSize },
  }
  if (attributes) {
    searchOptions.attributes = attributes
  }
  if (explicitBufferAttributes) {
    searchOptions.explicitBufferAttributes = explicitBufferAttributes
  }

  const { searchEntries } = await client.search(userSearchBase, searchOptions)

  let users = searchEntries || []
  for (let user of users) {
    _toBase64Attributes(user, attributes, explicitBufferAttributes)
  }
  return users
}

async function authenticateWithAdmin(options) {
  const { username, ldapOpts } = options
  let ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(options.adminDn, options.adminPassword, {
      starttls: options.starttls,
      ldapOpts,
    })
  } catch (error) {
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'admin bind failed'],
      ldapAdminClient
    )
  }

  try {
    let searchResult = await _searchUser(ldapAdminClient, options)

    let user = searchResult.user

    if (!user || !user.dn) {
      ldapOpts.log &&
        ldapOpts.log.trace(
          `admin did not find user! (${options.usernameAttribute}=${username})`
        )
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
      ldapUserClient = await _ldapBind(userDn, options.userPassword, {
        starttls: options.starttls,
        ldapOpts,
      })
    } catch (error) {
      return new AuthenticationResult(
        AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
        username,
        null,
        [
          authenticationMessages.AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
          error.message || 'invalid credentials',
        ],
        ldapAdminClient
      )
    }
    try {
      await _attachGroups(ldapAdminClient, user, options)
      return new AuthenticationResult(
        AUTH_RESULT_SUCCESS,
        username,
        user,
        [authenticationMessages.AUTH_RESULT_SUCCESS],
        ldapAdminClient
      )
    } finally {
      await ldapUserClient.unbind()
    }
  } finally {
    await ldapAdminClient.unbind()
  }
}

async function authenticateWithUser(options) {
  const { username, usernameAttribute, userSearchBase, ldapOpts } = options
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(options.userDn, options.userPassword, {
      starttls: options.starttls,
      ldapOpts,
    })
  } catch (error) {
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'user bind failed'],
      ldapUserClient
    )
  }
  try {
    if (!usernameAttribute || !userSearchBase) {
      // if usernameAttribute is not provided, no user detail is needed.
      return new AuthenticationResult(
        AUTH_RESULT_SUCCESS,
        username,
        {},
        [authenticationMessages.AUTH_RESULT_SUCCESS],
        ldapUserClient
      )
    }

    let searchResult = await _searchUser(ldapUserClient, options)

    let user = searchResult.user

    if (!user || !user.dn) {
      ldapOpts.log &&
        ldapOpts.log.trace(
          `user logged in, but user details could not be found. (${usernameAttribute}=${username}). Probabaly wrong attribute or searchBase?`
        )
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
    await _attachGroups(ldapUserClient, user, options)

    return new AuthenticationResult(
      AUTH_RESULT_SUCCESS,
      username,
      user,
      [authenticationMessages.AUTH_RESULT_SUCCESS],
      ldapUserClient
    )
  } finally {
    await ldapUserClient.unbind()
  }
}

async function verifyUserExists(options) {
  const { username, ldapOpts } = options
  let ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(options.adminDn, options.adminPassword, {
      starttls: options.starttls,
      ldapOpts,
    })
  } catch (error) {
    return new AuthenticationResult(
      AUTH_RESULT_FAILURE,
      username,
      null,
      [authenticationMessages.AUTH_RESULT_FAILURE, error.message || 'admin bind failed'],
      ldapAdminClient
    )
  }

  try {
    let searchResult = await _searchUser(ldapAdminClient, options)

    let user = searchResult.user

    if (!user || !user.dn) {
      ldapOpts.log &&
        ldapOpts.log.trace(
          `admin did not find user! (${options.usernameAttribute}=${username})`
        )
      return new AuthenticationResult(
        AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
        username,
        null,
        [
          authenticationMessages.AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
          'user not found or usernameAttribute is wrong',
        ],
        ldapAdminClient
      )
    }
    await _attachGroups(ldapAdminClient, user, options)
    return new AuthenticationResult(
      AUTH_RESULT_SUCCESS,
      username,
      user,
      [authenticationMessages.AUTH_RESULT_SUCCESS],
      ldapAdminClient
    )
  } finally {
    await ldapAdminClient.unbind()
  }
}

// validate the options of authenticate()/authenticateResult() and throw a
// single LdapAuthenticationError listing all missing fields at once
function _validateOptions(options) {
  if (!options) {
    throw new LdapAuthenticationError('authenticate: options object is required')
  }

  let missing = []
  if (!options.ldapOpts || !options.ldapOpts.url) {
    missing.push('ldapOpts.url')
  }

  if (options.verifyUserExists) {
    if (!options.adminDn) missing.push('adminDn')
    if (!options.adminPassword) missing.push('adminPassword')
    if (!options.userSearchBase) missing.push('userSearchBase')
    if (!options.usernameAttribute && !options.usernameFilter) {
      missing.push('usernameAttribute or usernameFilter')
    }
    if (!options.username) missing.push('username')
  } else if (options.adminDn) {
    if (!options.adminPassword) missing.push('adminPassword')
    if (!options.userSearchBase) missing.push('userSearchBase')
    if (!options.usernameAttribute && !options.usernameFilter) {
      missing.push('usernameAttribute or usernameFilter')
    }
    if (!options.username) missing.push('username')
    if (!options.userPassword) missing.push('userPassword')
  } else if (options.userDn) {
    if (!options.userPassword) missing.push('userPassword')
  } else {
    missing.push('adminDn or userDn')
  }

  if (missing.length > 0) {
    throw new LdapAuthenticationError(
      `authenticate: missing required option(s): ${missing.join(', ')}`
    )
  }
}

/**
 * Fetch all users under `userSearchBase`, using the admin account to search.
 * No individual username or password is required. The search always uses
 * LDAP paged results, so the common server-side limit of 1000 entries does
 * not apply. Returns an empty array if no user matches.
 *
 * @param {FetchUsersOptions} options - required: `ldapOpts` (with `url`),
 *   `adminDn`, `adminPassword`, `userSearchBase`; optional: `userFilter`,
 *   `attributes`, `explicitBufferAttributes`, `pageSize`, `starttls`.
 *   See the types in index.d.ts and the README for details.
 * @returns {Promise<LdapUserEntry[]>} one entry per matched user, each with
 *   its `dn` and the returned attributes.
 * @throws {LdapAuthenticationError} if required options are missing, or if
 *   the admin bind or the search fails.
 */
async function fetchUsers(options) {
  let missing = []
  if (!options.ldapOpts || !options.ldapOpts.url) missing.push('ldapOpts.url')
  if (!options.adminDn) missing.push('adminDn')
  if (!options.adminPassword) missing.push('adminPassword')
  if (!options.userSearchBase) missing.push('userSearchBase')
  if (missing.length > 0) {
    throw new LdapAuthenticationError(
      `fetchUsers: missing required option(s): ${missing.join(', ')}`
    )
  }

  let ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(options.adminDn, options.adminPassword, {
      starttls: options.starttls,
      ldapOpts: options.ldapOpts,
    })
  } catch (error) {
    throw new LdapAuthenticationError(error.message || 'admin bind failed')
  }

  try {
    return await _fetchAllUsers(ldapAdminClient, options)
  } catch (error) {
    throw new LdapAuthenticationError(error.message || 'user search failed')
  } finally {
    if (ldapAdminClient) {
      await ldapAdminClient.unbind()
    }
  }
}

/**
 * Authenticate a user against the LDAP server.
 *
 * Modes (see the README for a full option reference):
 * - Admin mode: `adminDn` + `adminPassword` + `userSearchBase` +
 *   `usernameAttribute` (or `usernameFilter`) + `username` + `userPassword`.
 *   The library binds as admin, finds the user's DN, then binds as the user.
 * - Self mode: `userDn` + `userPassword`. Optionally `userSearchBase` and
 *   `usernameAttribute` to also return the user's details.
 * - Verify mode: `verifyUserExists: true` with admin credentials; verifies
 *   that the user exists without checking the password.
 *
 * @param {AuthenticationOptions} options
 * @returns {Promise<any>} the user object if authentication succeeded.
 * @throws {LdapAuthenticationError} if authentication failed (its `code`
 *   property then holds the corresponding AUTH_RESULT_* constant) or if
 *   required options are missing.
 */
async function authenticate(options) {
  const result = await authenticateResult(options)

  if (result.code !== AUTH_RESULT_SUCCESS) {
    throw new LdapAuthenticationError(
      result.messages[result.messages.length - 1],
      result.code
    )
  }

  return result.user
}

/**
 * Same options and behavior as {@link authenticate}, but never throws on
 * authentication failure - it returns an {@link AuthenticationResult} whose
 * `code` identifies the outcome (useful for custom error handling).
 *
 * @param {AuthenticationOptions} options
 * @returns {Promise<AuthenticationResult>}
 * @throws {LdapAuthenticationError} if required options are missing;
 *   network errors from the LDAP server propagate as-is.
 */
async function authenticateResult(options) {
  _validateOptions(options)

  if (options.verifyUserExists) {
    return await verifyUserExists(options)
  }

  if (options.adminDn) {
    return await authenticateWithAdmin(options)
  }

  return await authenticateWithUser(options)
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
module.exports.fetchUsers = fetchUsers
module.exports.LdapAuthenticationError = LdapAuthenticationError

module.exports.exportForTesting = {
  _ldapEscapeDN,
}

import ldapAuthentication from './index.js'

export {
  AUTH_RESULT_FAILURE,
  AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
  AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
  AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
  AUTH_RESULT_FAILURE_UNCATEGORIZED,
  AUTH_RESULT_SUCCESS,
  AuthenticationResult,
  LdapAuthenticationError,
  authenticate,
  authenticateResult,
  fetchUsers,
} from './index.js'

export default ldapAuthentication

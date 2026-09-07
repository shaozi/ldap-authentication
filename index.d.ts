import { ClientOptions } from 'ldapts'

declare module 'ldap-authentication' {
  export interface AuthenticationOptions {
    ldapOpts: ClientOptions
    userDn?: string
    adminDn?: string
    adminPassword?: string
    userSearchBase?: string
    usernameAttribute?: string
    usernameFilter?:string
    username?: string
    verifyUserExists?: boolean
    starttls?: boolean
    groupsSearchBase?: string
    groupClass?: string
    groupMemberAttribute?: string
    groupMemberUserAttribute?: string
    userPassword?: string
    attributes?: string[]
    explicitBufferAttributes?: string[]
  }

  export const AUTH_RESULT_FAILURE = 0
  export const AUTH_RESULT_SUCCESS = 1
  export const AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND = -1
  export const AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS = -2
  export const AUTH_RESULT_FAILURE_CREDENTIAL_INVALID = -3
  export const AUTH_RESULT_FAILURE_UNCATEGORIZED = -4

  export class AuthenticationResult {
    constructor(authCode: number, identity: string, user: any, messages: string[], client: any)
    readonly code: number
    readonly identity: string
    readonly user: any
    readonly messages: string[]
    readonly client: any
  }

  /**
   * A single group entry returned on `user.groups` when group lookup is
   * enabled (`groupsSearchBase` + `groupClass`). `objectName` mirrors `dn`
   * for backward compatibility with the old ldapjs-based API.
   */
  export interface LdapGroupEntry {
    dn: string
    objectName?: string
    [attr: string]: any
  }

  /**
   * A single user object returned by `authenticate()` / `fetchUsers()`.
   * Always contains the entry's `dn`; other attribute values are
   * `string`/`string[]` (or a base64 string for `;binary` attributes), and
   * `groups` is present when group lookup is enabled.
   */
  export interface LdapUserEntry {
    dn: string
    groups?: LdapGroupEntry[]
    [attr: string]: any
  }

  export interface FetchUsersOptions {
    ldapOpts: ClientOptions
    adminDn: string
    adminPassword: string
    userSearchBase: string
    /**
     * LDAP search filter used to select the users to return.
     * Defaults to `(|(uid=*)(sAMAccountName=*))`, which matches both
     * POSIX (`uid`) and Active Directory (`sAMAccountName`) users.
     * Example: `'(objectClass=person)'`, or `'(objectClass=*)'` to match everything.
     */
    userFilter?: string
    /** A list of attributes of the users to be returned from the LDAP server. If omitted, all details will be returned. */
    attributes?: string[]
    /** A list of attributes to be returned as base64-encoded strings. */
    explicitBufferAttributes?: string[]
    /** Number of entries to fetch per page for the paged search. Defaults to 1000. */
    pageSize?: number
    starttls?: boolean
  }

  /**
   * Authenticate a user against the LDAP server. Kept as `Promise<any>` for
   * backward compatibility; the resolved value has the shape of
   * {@link LdapUserEntry}. Throws {@link LdapAuthenticationError} on failure.
   */
  export function authenticate(options: AuthenticationOptions): Promise<any>
  /** Same options as {@link authenticate} but never throws on failure; returns an {@link AuthenticationResult}. */
  export function authenticateResult(options: AuthenticationOptions): Promise<AuthenticationResult>

  /**
   * Bind with the admin account and search all users under `userSearchBase`.
   * The search always uses paged results, so results are not limited by the
   * common server-side limit of 1000 entries.
   *
   * Returns an empty array if no user matches the filter.
   */
  export function fetchUsers(options: FetchUsersOptions): Promise<LdapUserEntry[]>

  export class LdapAuthenticationError extends Error {
    constructor(message: any)
    name: string
  }
}

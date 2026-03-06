import { ClientOptions } from 'ldapts'

declare module 'ldap-authentication' {
  export interface AuthenticationOptions {
    ldapOpts: ClientOptions
    userDn?: string
    adminDn?: string
    adminPassword?: string
    userSearchBase?: string
    usernameAttribute?: string
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

  export function authenticate(options: AuthenticationOptions): Promise<any>
  export function authenticateResult(options: AuthenticationOptions): Promise<AuthenticationResult>

  export class LdapAuthenticationError extends Error {
    constructor(message: any)
    name: string
  }
}

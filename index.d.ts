import { ClientOptions } from 'ldapjs'

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
  }

  export function authenticate(options: AuthenticationOptions): Promise<any>

  export class LdapAuthenticationError extends Error {
    constructor(message: any)
    name: string
  }
}

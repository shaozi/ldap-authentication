declare module 'ldap-authentication' {
  type LDAPOpts = {
    url: string
    tlsOptions?: {
      rejectUnauthorized: boolean
    }
    connectTimeout?: number
  }
  export type AuthenticationOptions = {
    ldapOpts: LDAPOpts
    userDn?: string
    adminDn?: string
    adminPassword?: string
    userSearchBase?: string
    usernameAttribute?: string
    username?: string
    verifyUserExists?: boolean
    starttls?: Boolean
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

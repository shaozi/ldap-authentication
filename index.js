const assert = require('assert')
const ldap = require('ldapjs')

// bind and return the ldap client
function _ldapBind(dn, password, starttls, ldapOpts) {
  return new Promise(function (resolve, reject) {
    var client = ldap.createClient(ldapOpts)
    if (starttls) {
      client.starttls(ldapOpts.tlsOptions, null, function (error) {
        if (error) {
          reject(error.message)
          return
        }
        client.bind(dn, password, function (err) {
          if (err) {
            reject(err.message)
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
          reject(err.message)
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
async function _searchUser(ldapClient, searchBase, usernameFilter) {
  return new Promise(function (resolve, reject) {
    ldapClient.search(searchBase, {
      filter: usernameFilter,
      scope: 'sub'
    }, function (err, res) {
      var user = null
      if (err) {
        reject(err.message)
        ldapClient.unbind()
        return
      }
      res.on('searchEntry', function (entry) {
        user = entry.object
      });
      res.on('searchReference', function (referral) {
        console.log('referral: ' + referral.uris.join());
      });
      res.on('error', function (err) {
        console.error('error: ' + err.message);
        reject(err.message)
        ldapClient.unbind()
      });
      res.on('end', function (result) {
        if (result.status != 0) {
          reject('search failed')
        } else {
          //console.error('status = 0' + result);
          resolve(user)
        }
        ldapClient.unbind()
      })
    })
  })
}

async function authenticateWithAdmin(adminDn, adminPassword, userSearchBase, userSearchString, userPassword, starttls, ldapOpts) {
  var ldapAdminClient = await _ldapBind(adminDn, adminPassword, starttls, ldapOpts)
  var user = await _searchUser(ldapAdminClient, userSearchBase, userSearchString)
  ldapAdminClient.unbind()
  if (!user || !user.dn) {
    throw new Error('user not found or userSearchString is wrong')
  }
  var userDn = user.dn
  let ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  ldapUserClient.unbind()
  return user
}

async function authenticateWithUser(userDn, userSearchBase, userSearchString, userPassword, starttls, ldapOpts) {
  let ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  var user = await _searchUser(ldapUserClient, userSearchBase, userSearchString)
  if (!user || !user.dn) {
    throw new Error('user not found')
  }
  ldapUserClient.unbind()
  return user
}

async function authenticate(options) {
  assert(options.userSearchBase, 'userSearchBase must be provided')
  assert(options.userSearchString, 'userSearchString must be provided')
  assert(options.userPassword, 'userPassword must be provided')
  assert(options.ldapOpts && options.ldapOpts.url, 'ldapOpts.url must be provided')
  if (options.adminDn) {
    assert(options.adminPassword, 'adminDn and adminPassword must be both provided.')
    return await authenticateWithAdmin(
      options.adminDn,
      options.adminPassword,
      options.userSearchBase,
      options.userSearchString,
      options.userPassword,
      options.starttls,
      options.ldapOpts
    )
  }
  assert(options.userDn, 'adminDn/adminPassword OR userDn must be provided')
  return await authenticateWithUser(
    options.userDn,
    options.userSearchBase,
    options.userSearchString,
    options.userPassword,
    options.starttls,
    options.ldapOpts
  )
}

module.exports.authenticate = authenticate


FROM osixia/openldap:1.5.0

# Seed the test directory (dc=example,dc=com) with the users, groups and
# admin account used by the integration tests, and grant the test admin
# (cn=read-only-admin) the rights it needs. Files are applied by the
# osixia/openldap bootstrap at the container's first start.
COPY docker/ldap/10-ldap-test-data.ldif docker/ldap/20-ldap-test-acl.ldif /container/service/slapd/assets/config/bootstrap/ldif/custom/

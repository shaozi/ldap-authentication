# To Developers

This project is opensourced on BSD clauses.

You can do whatever you want with it, including open bugs, feature requests, add/remove codes, etc.

Issues are welcome. But due to the nature of an opensource project,
please be prepared that you may be asked to do a favor to provide a pull request to
implement it.

If you decide to contribute to the code base, here are some points to follow:

1. Requirements: Node.js 22 or above and Docker (for the seeded test LDAP server).
2. Run `npm install` to install the dependencies.
3. The test cases are integration tests in the `test/` folder, running against a
   seeded OpenLDAP container (see `docker-compose.yml` and `docker/ldap/*.ldif`).
   `npm run test:local` starts the container, waits until it is ready, runs the
   whole suite and stops the container again - run it locally before pushing.
4. If you add a feature, please see if you can create a test case to cover it.
5. This project uses a github action to run the integration tests on different
   NodeJS versions. Make sure that the test is passed.
6. If a new feature is added, please also write some document and example to
   explain what it is about and how to use it. The document and example should
   be in the `README.md` so users can easily find it.
7. The test data is seeded at container build time (`docker/ldap/*.ldif`): if you
   change it, rebuild the container first with `docker compose -f docker-compose.yml build`.

> May the force be with you!

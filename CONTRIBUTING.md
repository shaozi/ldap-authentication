# To Developers

This project is opensourced on BSD clauses. 

You can do whatever you want with it, including open bugs, feature requests, add/remove codes, etc.

Issues are welcome. But due to the nature of an opensource project, 
please be prepared that you may be asked to do a favor to provide a pull request to
implement it.

If you decide to contribute to the code base, here are some points to follow:

1. This project uses VSCode's devcontainer. You will need a container environment to use that. 
2. In VSCode, once open the project, it will prompt you to open it in container, open it in container
3. The dev environment should be up and running. 
   It includes a open ldap server container that has a few users pre-configured for you to test with. 
   Feel free to add more attributes in it for more test scenarios.
4. The test cases are in `test` folder, `test.js`. If you add a feature, please see if you can create
   a test case to cover it.
5. Use `npm run test` to run all the tests.
6. This project use github action to run integration tests on different NodeJS versions. Make sure that test
   is passed.
7. If a new feature is added, please also write some document and example to explain what it is about and how to use it.
   The document and example should be in the `README.md` so users can easily find it.
   
> May the force be with you!

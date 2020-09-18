var Jasmine = require('jasmine')
var jasmine = new Jasmine()

jasmine.loadConfig({
  spec_dir: 'test',
  spec_files: ['test.js'],
  random: false,
  seed: null,
  stopSpecOnExpectationFailure: false,
})

const Reporter = require('jasmine-console-reporter')

jasmine.jasmine.getEnv().addReporter(new Reporter())
jasmine.execute()

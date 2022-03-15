var Jasmine = require('jasmine')
var jasmine = new Jasmine()

jasmine.loadConfig({
  spec_dir: 'test',
  spec_files: ['test.js'],
  random: false,
  seed: null,
  stopSpecOnExpectationFailure: false,
})

class MyConsoleReporter {
  constructor() {
    this.suiteSeq = 1
  }

  _indentPrint(str) {
    str
      .trim()
      .split('\n')
      .forEach((line) => {
        process.stdout.write('       ' + line + '\n')
      })
  }

  jasmineStarted(suiteInfo) {
    console.log(`Running suite with ${suiteInfo.totalSpecsDefined} tests.`)
  }

  suiteStarted(result) {
    console.log(`\n${this.suiteSeq}. ${result.fullName}`)
    this.suiteSeq++
  }

  specStarted(result) {
    process.stdout.write(`   - ${result.description} `)
  }

  specDone(result) {
    process.stdout.write(
      ` ${result.status} [${result.passedExpectations.length}] (${result.duration} ms)`
    )

    for (var i = 0; i < result.failedExpectations.length; i++) {
      console.log()
      this._indentPrint(result.failedExpectations[i].message)
      this._indentPrint(result.failedExpectations[i].stack)
    }

    process.stdout.write(`\n`)
  }

  jasmineDone(result) {
    console.log('Overall result: ' + result.overallStatus)
    for (var i = 0; i < result.failedExpectations.length; i++) {
      console.log('Global ' + result.failedExpectations[i].message)
      console.log(result.failedExpectations[i].stack)
    }
  }
}

jasmine.jasmine.getEnv().addReporter(new MyConsoleReporter())
jasmine.execute()

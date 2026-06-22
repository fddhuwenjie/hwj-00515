let currentSuite = null;
const stack = [];

const state = {
  suites: []
};

function describe(name, fn) {
  const suite = { name, tests: [], before: [], after: [], beforeEach: [], afterEach: [], parent: currentSuite };
  state.suites.push(suite);
  stack.push(currentSuite);
  currentSuite = suite;
  fn();
  currentSuite = stack.pop();
}

function it(name, fn) {
  if (!currentSuite) {
    throw new Error('it() must be called inside describe()');
  }
  currentSuite.tests.push({ name, fn });
}

function before(fn) {
  if (currentSuite) currentSuite.before.push(fn);
}

function after(fn) {
  if (currentSuite) currentSuite.after.push(fn);
}

function beforeEach(fn) {
  if (currentSuite) currentSuite.beforeEach.push(fn);
}

function afterEach(fn) {
  if (currentSuite) currentSuite.afterEach.push(fn);
}

module.exports = {
  describe, it, before, after, beforeEach, afterEach, state
};

const fs = require('fs');
const path = require('path');

const TEST_DIR = __dirname;
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m'
};

function color(text, c) {
  return COLORS[c] + text + COLORS.reset;
}

const stats = {
  total: 0,
  passed: 0,
  failed: 0,
  skipped: 0,
  suites: 0,
  failures: []
};

async function runSuite(suite, indent) {
  stats.suites++;
  console.log('\n' + indent + color(suite.name, 'bold') + color(' (suite)', 'dim'));
  const subIndent = indent + '  ';

  for (const hook of suite.before) await runHook(hook, subIndent);

  for (const test of suite.tests) {
    stats.total++;
    for (const hook of suite.beforeEach) await runHook(hook, subIndent);

    const start = Date.now();
    try {
      await test.fn();
      const elapsed = Date.now() - start;
      stats.passed++;
      console.log(subIndent + color('✓', 'green') + ' ' + test.name + color(` (${elapsed}ms)`, 'dim'));
    } catch (err) {
      stats.failed++;
      stats.failures.push({ suite: suite.name, test: test.name, error: err });
      console.log(subIndent + color('✗', 'red') + ' ' + test.name + color(' FAILED', 'red'));
      console.log(subIndent + '  ' + color(err.message || String(err), 'dim'));
    }

    for (const hook of suite.afterEach) await runHook(hook, subIndent);
  }

  for (const hook of suite.after) await runHook(hook, subIndent);
}

async function runHook(fn, indent) {
  try {
    await fn();
  } catch (err) {
    console.log(indent + color('Hook error: ' + (err.message || String(err)), 'red'));
  }
}

function loadTestFiles() {
  const files = fs.readdirSync(TEST_DIR)
    .filter(f => f.endsWith('.test.js'))
    .sort();

  console.log(color(`\nFound ${files.length} test file(s)`, 'cyan'));

  for (const file of files) {
    const filePath = path.join(TEST_DIR, file);
    try {
      require(filePath);
    } catch (err) {
      console.log(color(`  Error loading ${file}: ${err.message}`, 'red'));
      if (err.stack) console.log(color(err.stack.split('\n').slice(1, 4).join('\n'), 'dim'));
    }
  }
}

async function runAll() {
  const { state } = require('./harness');
  for (const suite of state.suites) {
    await runSuite(suite, '');
  }
  printSummary();
}

function printSummary() {
  console.log('\n' + '='.repeat(60));
  console.log(color('TEST SUMMARY', 'bold'));
  console.log('='.repeat(60));
  console.log(`  Suites:   ${stats.suites}`);
  console.log(`  Total:    ${stats.total}`);
  console.log(`  Passed:   ${color(stats.passed.toString(), 'green')}`);
  console.log(`  Failed:   ${color(stats.failed.toString(), stats.failed > 0 ? 'red' : 'dim')}`);

  if (stats.failures.length > 0) {
    console.log('\n' + color('FAILURES:', 'red'));
    for (const f of stats.failures) {
      console.log(`\n  ${f.suite} > ${color(f.test, 'red')}`);
      if (f.error && f.error.stack) {
        const lines = f.error.stack.split('\n').slice(0, 8);
        for (const line of lines) {
          console.log('    ' + color(line, 'dim'));
        }
      } else {
        console.log('    ' + color(f.error && f.error.message ? f.error.message : String(f.error), 'dim'));
      }
    }
  }

  console.log('');
  if (stats.failed === 0) {
    console.log(color('  ✓ All tests passed!', 'green') + '\n');
    process.exit(0);
  } else {
    console.log(color(`  ✗ ${stats.failed} test(s) failed`, 'red') + '\n');
    process.exit(1);
  }
}

function ensureSamplesGenerated() {
  const { SAMPLES_DIR } = require('./helpers');
  if (!fs.existsSync(SAMPLES_DIR) || fs.readdirSync(SAMPLES_DIR).length < 5) {
    console.log(color('Generating test samples...', 'yellow'));
    require('./generate_test_samples');
  }
}

ensureSamplesGenerated();
loadTestFiles();

process.on('uncaughtException', (err) => {
  console.log(color('\nUncaught exception: ' + (err.message || String(err)), 'red'));
  if (err.stack) console.log(color(err.stack, 'dim'));
  process.exit(1);
});

runAll();

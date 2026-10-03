#!/usr/bin/env node
'use strict';

/**
 * Contract test for the npm pre-publish gate.
 *
 * Run 37120521494 published nothing and produced no diagnosis. `npm publish`
 * ran `prepublishOnly` -> `npm run test:all` -> the old `test:tarball` step,
 * which shelled out to `npm pack` a second time from inside a lifecycle script
 * that was already inside npm. The nested call inherited `npm_config_*` and
 * `npm_command=publish` and returned no parseable output; the script reported a
 * generic parse failure and then called `process.exit(1)` immediately after
 * writing to a pipe, so the queued stderr write was discarded. npm surfaced
 * only `npm error command failed`.
 *
 * This asserts the properties that make that class of failure impossible to
 * repeat silently. It reads the gate source; it does not publish.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const GATE = path.join(ROOT, 'bin', 'prepublish_gate.js');
const source = fs.readFileSync(GATE, 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

let failures = 0;

function check(name, fn) {
  try {
    fn();
    process.stdout.write(`PASS  ${name}\n`);
  } catch (err) {
    failures += 1;
    process.stdout.write(`FAIL  ${name}\n        ${err.message}\n`);
  }
}

function assertMatch(pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

check('the gate exists and parses', () => {
  if (source.length < 100) throw new Error('gate source looks truncated');
});

/**
 * Strip comments and string literals from JavaScript source.
 *
 * The gate's header deliberately explains *why* it avoids process.exit() and
 * names npm_config_dry_run, so a naive text search over the raw file flags its
 * own documentation. Comments are removed first; string literals second, since
 * the failure messages themselves contain the words being searched for.
 */
function executableLines(text) {
  const stripped = [];
  for (const line of text.split('\n')) {
    // Continuation lines of a /* ... */ block start with `*`.
    let body = /^\s*\*/.test(line) ? '' : line;
    body = body.replace(/\/\*.*?\*\//g, '').replace(/\/\/.*$/, '');
    stripped.push(
      body.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""'),
    );
  }
  return stripped.join('\n');
}

const CODE = executableLines(source);

check('the gate never calls process.exit()', () => {
  // process.exit() discards writes still queued on a pipe, which is how the
  // real failure lost its entire diagnostic.
  const match = /\bprocess\s*\.\s*exit\s*\(/.exec(CODE);
  if (match !== null) {
    const line = CODE.slice(0, match.index).split('\n').length;
    throw new Error(`process.exit( found at line ${line}; use process.exitCode`);
  }
});

check('the gate sets process.exitCode explicitly', () => {
  assertMatch(/process\.exitCode\s*=/, 'the gate never assigns process.exitCode');
});

check('the gate always checks the npm exit status', () => {
  if (!/ok:\s*result\.status\s*===?\s*0/.test(CODE)) {
    throw new Error('the npm exit status is never compared; a non-zero npm run was invisible');
  }
  // The status has to feed the ok flag rather than being merely computed:
  // replacing the comparison with a literal `true` must be caught.
  if (!/\bok\b\s*:/.test(CODE)) {
    throw new Error('runNpm returns no ok flag derived from the exit status');
  }
});

check('every npm invocation reports its command, exit code and output on failure', () => {
  assertMatch(
    /exit code:/,
    'the failure detail does not include the exit code',
  );
  assertMatch(
    /command:/,
    'the failure detail does not include the command that was run',
  );
  assertMatch(
    /stdout bytes:/,
    'the failure detail does not report how much output was captured',
  );
});

check('the gate reports rather than swallowing an unstartable npm', () => {
  assertMatch(
    /could not locate npm-cli\.js/,
    'no message for npm being unresolvable',
  );
  assertMatch(
    /reason\s*:/,
    'runNpm never returns a reason for a failed start',
  );
});

check('the gate strips npm_config_* from nested npm calls', () => {
  // Under `npm publish --dry-run`, npm sets npm_config_dry_run=true. A nested
  // `npm pack` that inherits it reports success while writing no tarball, and
  // the gate then fails on "found 0 tarballs" for a reason unrelated to the
  // package. This is the difference between the gate working and not working
  // inside a lifecycle, so it is asserted explicitly.
  if (!/npm_config_/.test(source)) {
    throw new Error('the gate never mentions npm_config_');
  }
  if (!/delete\s+env\[key\]/.test(source) && !/startsWith\('npm_config_'\)/.test(source)) {
    throw new Error('the gate does not remove npm_config_* from the nested environment');
  }
  assertMatch(
    /npm_config_dry_run/,
    'the gate does not name the specific variable that suppresses tarball writes',
  );
});

check('the gate works the same in both publish modes', () => {
  // PA_PUBLISH_MODE only ever reaches verify_installed_launcher.js, which read
  // it in the previous revision. The gate must not consult it, or a publish
  // could take a different code path than CI verified.
  if (/PA_PUBLISH_MODE/.test(source)) {
    throw new Error('the gate reads PA_PUBLISH_MODE; it must behave identically in both modes');
  }
});

check('the gate parses npm stdout only, never stdout+stderr', () => {
  // Run 37129620610: npm exited 0 and wrote a valid tarball, but the gate read
  // "no parseable file list" because it concatenated stderr onto stdout before
  // parsing. Any future concatenation inside the parser reintroduces the bug.
  //
  // Scope this to the parser body: the gate legitimately joins the two streams
  // when composing a diagnostic message, and that is not what broke.
  const body = /function parsePayload\([\s\S]*?\n\}/.exec(CODE);
  if (body === null) throw new Error('parsePayload could not be located in the gate');
  const parser = body[0];
  if (/stderr/.test(parser)) {
    throw new Error('parsePayload references stderr again; the payload must come from stdout only');
  }
  assertMatch(
    /result\.stdout\s*\|\|\s*''/,
    'the parser no longer reads the payload from result.stdout',
  );
});

check('the gate reports stderr on failure without parsing it', () => {
  assertMatch(
    /--- stderr ---/,
    'stderr is no longer shown in the failure detail',
  );
});

check('the lifecycle test exists and is wired into the chain', () => {
  const lifecycleTest = path.join(ROOT, 'bin', 'prepublish_lifecycle.test.js');
  if (!fs.existsSync(lifecycleTest)) {
    throw new Error('bin/prepublish_lifecycle.test.js is missing; the CI reproduction is gone');
  }
  const all = pkg.scripts['test:all'] || '';
  if (!all.includes('test:lifecycle')) {
    throw new Error(`test:all does not run the lifecycle test: ${all}`);
  }
  if (!(pkg.scripts['test:lifecycle'] || '').includes('prepublish_lifecycle.test.js')) {
    throw new Error(`test:lifecycle does not invoke the lifecycle test: ${pkg.scripts['test:lifecycle']}`);
  }
});

check('the gate uses the lifecycle-provided npm_execpath first', () => {
  // Inside a lifecycle script npm_execpath is set and correct on every platform;
  // without it the gate has to guess and can pick a shim it cannot execute.
  const execpathIndex = source.indexOf('npm_execpath');
  if (execpathIndex === -1) {
    throw new Error('the gate never consults npm_execpath');
  }
});

check('the gate covers the tarball allowlist and the required runtime files', () => {
  // The allowlist rules live in FORBIDDEN_PATTERNS as regular expressions, so
  // match their source text rather than expecting bare literal substrings.
  const needles = [
    '__pycache__',
    'node_modules',
    'pyc', // from /\.(pyc|pyo|tgz)$/
    'bin/plan-auditor.js',
    'supervisor/cli.py',
    'scripts/audit_check.py',
  ];
  for (const needle of needles) {
    if (!source.includes(needle)) {
      throw new Error(`the gate no longer checks for ${needle}`);
    }
  }
});

check('the gate covers the caller-cwd defect (npm 2.4.1)', () => {
  // Assert the behaviour, not the wording: the installed bin must be spawned
  // with cwd set to the throwaway workspace, a non-zero exit must fail, and the
  // wrong-directory report must be detected. A reworded message is fine.
  if (!/cwd:\s*workspace/.test(CODE)) {
    throw new Error('the gate no longer runs the installed CLI from the throwaway workspace');
  }
  if (!/probe\.status\s*!==\s*0/.test(CODE)) {
    throw new Error('the gate no longer fails when the installed launcher cannot validate');
  }
  if (!/plan yok|plan not found/.test(CODE)) {
    throw new Error('the gate no longer detects the wrong-directory report');
  }
});

check('the gate covers the exit-code defect (npm 2.4.0 class)', () => {
  assertMatch(
    /failing verifier propagates/,
    'the gate no longer asserts that a failing verifier propagates',
  );
});

check('prepublishOnly runs the gate', () => {
  const pre = pkg.scripts.prepublishOnly;
  if (pre !== 'npm run test:all') {
    throw new Error(`prepublishOnly is ${pre}, expected "npm run test:all"`);
  }
  const all = pkg.scripts['test:all'] || '';
  if (!all.includes('test:gate')) {
    throw new Error(`test:all does not run test:gate: ${all}`);
  }
  // The gate must be reachable without indirection, so a dropped script entry is
  // a contract failure rather than a surprise at publish time.
  const gate = pkg.scripts['test:gate'] || '';
  if (!gate.includes('bin/prepublish_gate.js')) {
    throw new Error(`test:gate does not invoke the gate: ${gate}`);
  }
});

check('the consolidated gate replaced the two superseded scripts', () => {
  for (const removed of ['test:tarball', 'test:installed']) {
    if (pkg.scripts[removed] !== undefined) {
      throw new Error(`npm script ${removed} still exists; it shells out to npm again`);
    }
  }
  for (const superseded of ['bin/check_tarball_contents.js', 'bin/verify_installed_launcher.js']) {
    if (fs.existsSync(path.join(ROOT, superseded))) {
      throw new Error(`${superseded} still exists alongside the consolidated gate`);
    }
  }
});

check('the gate is invoked identically in CI and by prepublishOnly', () => {
  const workflow = fs.readFileSync(
    path.join(ROOT, '.github', 'workflows', 'npm-publish.yml'),
    'utf8',
  );
  // CI runs the gate directly; prepublishOnly reaches it through test:all.
  // Assert both, so neither path can quietly drop it.
  if (!workflow.includes('npm run test:gate')) {
    throw new Error('npm-publish.yml does not run the pre-publish gate');
  }
  const chain = [pkg.scripts['test:all'], pkg.scripts.prepublishOnly].join('\n');
  if (!chain.includes('test:gate')) {
    throw new Error('prepublishOnly no longer reaches the pre-publish gate');
  }
});

process.stdout.write(`\npre-publish-gate contract: ${failures} failure(s)\n`);
process.exitCode = failures === 0 ? 0 : 1;
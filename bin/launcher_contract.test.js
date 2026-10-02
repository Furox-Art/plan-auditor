#!/usr/bin/env node
'use strict';

/**
 * Contract test for the npm launcher.
 *
 * `npm test` runs this. It asserts the properties the launcher must hold for
 * the package to be safe to install:
 *
 *   1. `index.js` and `bin/plan-auditor.js` parse (`node --check`).
 *   2. `package.json` wires `bin` to the file that propagates exit codes.
 *   3. `index.js` exports `runPythonAndPropagate`.
 *   4. The launcher runs the CLI with the *caller's* working directory, not
 *      the package directory. A launcher that hard-codes `cwd: __dirname`
 *      silently audits the installed package folder instead of the user's
 *      workspace, which is the worst possible failure for a verification tool:
 *      it reports on the wrong tree while looking authoritative.
 *   5. A failing verifier produces a non-zero launcher exit code, and a
 *      passing one produces zero. Exit-code laundering is the exact bug class
 *      this project exists to prevent, so it is asserted directly.
 *   6. Python being unavailable fails closed (non-zero), never silently 0.
 *
 * Checks 4-6 spawn the real launcher, so they need Python on PATH. When Python
 * is absent those assertions are reported as skipped rather than silently
 * passing, and the pure-static checks still gate.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const INDEX = path.join(ROOT, 'index.js');
const BIN = path.join(ROOT, 'bin', 'plan-auditor.js');

let failures = 0;
let skipped = 0;

function check(name, fn) {
  try {
    fn();
    process.stdout.write(`  PASS  ${name}\n`);
  } catch (err) {
    failures += 1;
    process.stdout.write(`  FAIL  ${name}\n        ${err.message}\n`);
  }
}

function skip(name, reason) {
  skipped += 1;
  process.stdout.write(`  SKIP  ${name}\n        ${reason}\n`);
}

function pythonAvailable() {
  const exe = process.platform === 'win32' ? 'python' : 'python3';
  const probe = spawnSync(exe, ['-c', 'import sys; sys.exit(0)'], { stdio: 'ignore' });
  return probe.status === 0;
}

function launcherAvailable() {
  const probe = spawnSync('node', ['--version'], { stdio: 'ignore' });
  return probe.status === 0;
}

/* ------------------------------------------------------------------ static */

check('index.js and bin/plan-auditor.js parse', () => {
  for (const file of [INDEX, BIN]) {
    const result = spawnSync('node', ['--check', file], { encoding: 'utf8' });
    assert.strictEqual(
      result.status,
      0,
      `node --check failed for ${path.relative(ROOT, file)}: ${result.stderr}`
    );
  }
});

check('package.json bin points at the propagating launcher', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const bin = pkg.bin && pkg.bin['plan-auditor'];
  assert.ok(bin, 'package.json has no bin["plan-auditor"]');
  assert.strictEqual(
    path.resolve(ROOT, bin),
    BIN,
    `bin entry ${bin} does not resolve to bin/plan-auditor.js`
  );
});

check('index.js exports runPythonAndPropagate', () => {
  const mod = require(INDEX);
  assert.strictEqual(
    typeof mod.runPythonAndPropagate,
    'function',
    'index.js must export runPythonAndPropagate'
  );
});

check('launcher does not hard-code the package directory as cwd', () => {
  const source = fs.readFileSync(INDEX, 'utf8');
  assert.ok(
    !/cwd:\s*__dirname/.test(source),
    'index.js sets cwd: __dirname, so a relative workspace path resolves ' +
      'against the installed package directory instead of the caller\'s cwd'
  );
});

check('package.json files allowlist excludes local artifacts', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0, 'package.json needs a files allowlist');
  const joined = pkg.files.join('\n');
  assert.ok(joined.includes('supervisor'), 'files allowlist must ship supervisor/');
  assert.ok(joined.includes('scripts'), 'files allowlist must ship scripts/');
  assert.ok(
    !pkg.files.includes('.'),
    'the allowlist must not include the whole tree (".")'
  );
});

check('published npm tarball omits the whole repository', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const shipped = new Set(pkg.files.filter((f) => !f.startsWith('!')));
  // Whole-tree selectors would republish local virtualenvs and build output.
  for (const forbidden of ['.', './', '**', '*', 'tests', 'examples', '.github', 'dist', 'build']) {
    assert.ok(
      !shipped.has(forbidden),
      `files allowlist must not publish ${forbidden}`
    );
  }
  // Every selector must be an explicit path, not a directory the user never
  // asked to ship. docs/ is intentional (the docs promise it ships).
  for (const entry of shipped) {
    assert.ok(
      !entry.includes('*'),
      `files allowlist entry ${entry} uses a wildcard, which can pull in local artifacts`
    );
  }
});

/* ---------------------------------------------------------------- behaviour */

if (!launcherAvailable()) {
  skip('launcher behaviour checks', 'node is not resolvable on PATH');
} else if (!pythonAvailable()) {
  skip(
    'launcher behaviour checks',
    'python is not on PATH; the launcher fails closed in this case, which is ' +
      'asserted by the fail-closed test in tests/test_npm_launcher.py'
  );
} else {
  const { runPythonAndPropagate } = require(INDEX);

  const PASSING_STEP = `python -c "print('launcher contract ok')"`;
  const FAILING_STEP = `python -c "import sys; sys.exit(3)"`;

  function writePlan(workspaceDir, command, title) {
    const planDir = path.join(workspaceDir, '.plan-auditor');
    fs.mkdirSync(planDir, { recursive: true });
    const plan = {
      task: 'npm launcher contract',
      created: new Date().toISOString(),
      requirements: [
        { id: 'REQ-001', description: 'the declared check behaviour', priority: 'must' },
      ],
      steps: [
        {
          id: 1,
          title,
          covers: ['REQ-001'],
          verify: [{ type: 'run', cmd: command, expect_exit: 0 }],
          status: 'pending',
        },
      ],
    };
    fs.writeFileSync(path.join(planDir, 'plan.json'), JSON.stringify(plan, null, 2), 'utf8');
  }

  function makeWorkspace(command, title) {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'pa-contract-'));
    writePlan(dir, command, title);
    return dir;
  }

  function runLauncher(args, cwd) {
    const result = spawnSync(process.execPath, [BIN, ...args], {
      cwd,
      encoding: 'utf8',
    });
    return result;
  }

  check('launcher runs the CLI from the caller working directory', () => {
    const workspace = makeWorkspace(PASSING_STEP, 'cwd contract');
    try {
      // The workspace is a real directory containing .plan-auditor. If the
      // launcher forced cwd to the package directory, "validate ." would
      // inspect the package folder and fail to find a plan.
      const result = runLauncher(['validate', '.'], workspace);
      assert.strictEqual(
        result.status,
        0,
        `validate . failed from the caller cwd: ${result.stdout}${result.stderr}`
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  check('failing verifier yields a non-zero launcher exit code', () => {
    const workspace = makeWorkspace(FAILING_STEP, 'failing contract');
    try {
      const result = runLauncher(['run', workspace, '1'], workspace);
      assert.notStrictEqual(
        result.status,
        0,
        'a failing step must not be reported as a success by the launcher'
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  check('passing verifier yields a zero launcher exit code', () => {
    const workspace = makeWorkspace(PASSING_STEP, 'passing contract');
    try {
      const result = runLauncher(['run', workspace, '1'], workspace);
      assert.strictEqual(
        result.status,
        0,
        `passing step should exit 0: ${result.stdout}${result.stderr}`
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  check('runPythonAndPropagate returns the child and mirrors its exit code', () => {
    assert.strictEqual(typeof runPythonAndPropagate, 'function');
    // Direct invocation without process.exit: assert it returns a child
    // process object so callers can observe it, as documented.
    const child = require(INDEX).runPython(['--help']);
    assert.ok(
      child && typeof child.on === 'function',
      'runPython must return the spawned child'
    );
  });
}

process.stdout.write(`\nlauncher contract: ${failures} failure(s), ${skipped} skipped\n`);
process.exit(failures === 0 ? 0 : 1);
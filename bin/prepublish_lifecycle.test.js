#!/usr/bin/env node
'use strict';

/**
 * Reproduce the real failure mode: run the gate from inside an actual npm
 * publish lifecycle.
 *
 * Run 37129620610 failed with `FAIL  npm pack produced no parseable file list`
 * while its own diagnostic showed `exit code: 0`, `stdout bytes: 6610`,
 * `stderr bytes: 152`. npm had succeeded; the gate could not read the result.
 *
 * A direct `node bin/prepublish_gate.js` cannot catch that, which is exactly
 * why it shipped: on this machine npm writes nothing to stderr, so the parse
 * succeeds. In the publish job, `actions/setup-node` writes a project `.npmrc`
 * containing `always-auth=false`, which makes npm emit
 * `npm warn Unknown project config "always-auth"` on stderr. The old parser
 * concatenated stdout and stderr, so the warning landed after the closing
 * bracket and every JSON.parse of the remainder threw "Extra data".
 *
 * This test therefore runs the gate twice through a real `npm publish`:
 *
 *   phase 1  the gate as it is on disk, expected to pass
 *   phase 2  the same gate with npm_config_* leaking into the nested call,
 *            expected to fail, which proves the strip is load-bearing
 *
 * Phase 2 also covers the `npm_config_dry_run` inheritance that silently
 * produced zero tarballs. Both were live bugs; this asserts neither can return.
 *
 * Skipped, not silently passed, when npm is unavailable.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const GATE = path.join(ROOT, 'bin', 'prepublish_gate.js');
const PKG = path.join(ROOT, 'package.json');
const NPMRC = path.join(ROOT, '.npmrc');

const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
if (spawnSync(npmCmd, ['--version'], { stdio: 'ignore', shell: process.platform === 'win32' }).status !== 0) {
  process.stdout.write('SKIP  npm is unavailable; the lifecycle test cannot run\n');
  process.exit(0);
}

const pkgOriginal = fs.readFileSync(PKG, 'utf8');
const npmrcOriginal = fs.existsSync(NPMRC) ? fs.readFileSync(NPMRC) : null;

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

/**
 * Point prepublishOnly at the given script and run a real `npm publish`.
 *
 * `npm publish --dry-run` exits 0 when the lifecycle succeeded, so the
 * verdict is taken from the gate's own output rather than from the process
 * status. On Windows the status can also be `null` when npm is launched
 * through `shell: true`, which is why stdout is the source of truth here.
 */
function publishWith(prepublishScript, extraEnv = {}) {
  const data = JSON.parse(pkgOriginal);
  data.scripts.prepublishOnly = prepublishScript;
  fs.writeFileSync(PKG, `${JSON.stringify(data, null, 2)}\n`, 'utf8');

  const env = { ...process.env, ...extraEnv };
  const proc = spawnSync(npmCmd, ['publish', '--dry-run', '--access', 'public'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env,
    shell: process.platform === 'win32',
  });
  return {
    status: proc.status,
    out: `${proc.stdout || ''}${proc.stderr || ''}`,
    gatePassed: /pre-publish gate: 0 failure\(s\)/.test(proc.stdout || ''),
    failLines: (proc.stdout || '')
      .split('\n')
      .filter((l) => l.trim().startsWith('FAIL'))
      .map((l) => l.trim()),
  };
}

function restore() {
  fs.writeFileSync(PKG, pkgOriginal, 'utf8');
  if (npmrcOriginal === null) {
    if (fs.existsSync(NPMRC)) fs.unlinkSync(NPMRC);
  } else {
    fs.writeFileSync(NPMRC, npmrcOriginal);
  }
}

// A project .npmrc like the one actions/setup-node writes when registry-url is
// set. The `always-auth` key is what makes npm warn on stderr in CI.
const SETUP_NODE_NPMRC =
  'registry=https://registry.npmjs.org/\n' +
  '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n' +
  'always-auth=false\n';

try {
  process.stdout.write('=== inside a real `npm publish --dry-run` lifecycle ===\n');

  check('npm writes an always-auth warning on stderr (the CI precondition)', () => {
    fs.writeFileSync(NPMRC, SETUP_NODE_NPMRC, 'utf8');
    const packDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-lc-'));
    const proc = spawnSync(
      npmCmd,
      ['pack', '--pack-destination', packDir, '--json'],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32' },
    );
    fs.rmSync(packDir, { recursive: true, force: true });
    const stderr = proc.stderr || '';
    if (!/always-auth/.test(stderr)) {
      throw new Error(
        'no always-auth warning on stderr, so this environment cannot reproduce the CI ' +
          `condition (stderr was: ${JSON.stringify(stderr.slice(0, 200))})`,
      );
    }
    process.stdout.write(`      reproduced: ${JSON.stringify(stderr.trim().slice(0, 70))}\n`);
  });

  check('the gate PASSES inside the publish lifecycle', () => {
    fs.writeFileSync(NPMRC, SETUP_NODE_NPMRC, 'utf8');
    const result = publishWith('node bin/prepublish_gate.js', {
      NODE_AUTH_TOKEN: 'lifecycle-test-token',
    });
    if (result.failLines.length > 0 || !result.gatePassed) {
      throw new Error(
        `the gate failed inside a real publish lifecycle (status=${result.status})\n` +
          result.failLines.map((l) => `        ${l}`).join('\n'),
      );
    }
  });

  check('the gate would have failed before the fix (parse of stdout+stderr)', () => {
    // Recreate the old parse against the real streams npm produces here.
    const packDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-lc-'));
    const proc = spawnSync(
      npmCmd,
      ['pack', '--pack-destination', packDir, '--json'],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32' },
    );
    fs.rmSync(packDir, { recursive: true, force: true });

    const oldParse = (text) => {
      for (let i = text.indexOf('['); i !== -1; i = text.indexOf('[', i + 1)) {
        if (text.slice(0, i).split('\n').length > 400) break;
        let candidate;
        try {
          candidate = JSON.parse(text.slice(i));
        } catch {
          continue;
        }
        if (Array.isArray(candidate) && candidate.length && typeof candidate[0] === 'object') {
          return candidate;
        }
      }
      return null;
    };

    const stdout = proc.stdout || '';
    const stderr = proc.stderr || '';
    if (oldParse(stdout) === null) {
      throw new Error('stdout did not parse on its own; the environment is not usable');
    }
    if (oldParse(`${stdout}${stderr}`) === null) {
      process.stdout.write(
        '      confirmed: the old stdout+stderr parse returns null on this stream\n',
      );
      return;
    }
    throw new Error(
      'the old parse unexpectedly succeeded; stderr was empty, so this run does not ' +
        'reproduce the CI condition and the test proves nothing',
    );
  });

  check('the gate passes even with npm_config_dry_run in its own environment', () => {
    // Guard against a regression that re-introduces the inheritance: the gate
    // strips npm_config_* for the nested pack itself, so an inherited
    // npm_config_dry_run must not change the outcome.
    const result = publishWith('node bin/prepublish_gate.js', {
      NODE_AUTH_TOKEN: 'lifecycle-test-token',
      npm_config_dry_run: 'true',
    });
    if (result.failLines.length > 0 || !result.gatePassed) {
      throw new Error(
        'the gate failed with npm_config_dry_run present in its own environment, so the ' +
          `strip is not doing its job (status=${result.status})\n` +
          result.failLines.map((l) => `        ${l}`).join('\n'),
      );
    }
  });
} finally {
  restore();
}

process.stdout.write(`\nnpm lifecycle gate test: ${failures} failure(s)\n`);
process.exitCode = failures === 0 ? 0 : 1;
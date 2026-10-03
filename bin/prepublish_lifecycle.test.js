#!/usr/bin/env node
'use strict';

/**
 * Reproduce the real failure mode: run the gate from inside an actual npm
 * publish lifecycle, with npm writing to stderr the way it does in CI.
 *
 * Run 37129620610 failed with `FAIL  npm pack produced no parseable file list`
 * while its own diagnostic showed `exit code: 0`, `stdout bytes: 6610`,
 * `stderr bytes: 152`. npm had succeeded; the gate could not read the result.
 *
 * A direct `node bin/prepublish_gate.js` cannot catch that. `actions/setup-node`
 * writes `always-auth=false` into an npmrc, npm 11.19.0 rejects the key and
 * prints `npm warn Unknown user config "always-auth"` on stderr, and the old
 * parser concatenated stdout and stderr before parsing -- so the warning landed
 * after the closing bracket and every `JSON.parse` threw "Extra data".
 *
 * The stderr noise is raised here with `loglevel=verbose`, which makes npm log
 * its own invocation on stderr on every npm version. The specific warning npm
 * happens to print in CI is not the point: the point is that npm wrote to
 * stderr while stdout still carried the whole payload. Keying off a particular
 * unsupported config option only reproduces that on some runners -- npm 11 calls
 * it "user config" and older npm stays silent -- and an earlier version of this
 * test failed for exactly that reason.
 *
 * Phases:
 *   1  npm emits a warning on stderr (the CI precondition)
 *   2  the gate as it is on disk passes inside the lifecycle
 *   3  the pre-fix parse returns null on this very stream
 *   4  the gate passes with npm_config_dry_run in its own environment
 *
 * Skipped, not silently passed, when npm is unavailable.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const PKG = path.join(ROOT, 'package.json');
const NPMRC = path.join(ROOT, '.npmrc');

const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const useShell = process.platform === 'win32';

if (
  spawnSync(npmCmd, ['--version'], { stdio: 'ignore', shell: useShell }).status !== 0
) {
  process.stdout.write('SKIP  npm is unavailable; the lifecycle test cannot run\n');
  process.exit(0);
}

const pkgOriginal = fs.readFileSync(PKG, 'utf8');
const projectNpmrcOriginal = fs.existsSync(NPMRC) ? fs.readFileSync(NPMRC) : null;

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

/** Run npm pack the way the gate does, returning stdout and stderr separately. */
function realPack() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-lc-'));
  try {
    const proc = spawnSync(npmCmd, ['pack', '--pack-destination', dir, '--json'], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      shell: useShell,
    });
    return {
      status: proc.status,
      stdout: proc.stdout || '',
      stderr: proc.stderr || '',
      tarballs: fs.readdirSync(dir).filter((f) => f.endsWith('.tgz')).length,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Make npm log on stderr, so the gate reads a stream shaped like the one in CI:
 * a complete payload on stdout with diagnostics appended on stderr.
 *
 * `loglevel=verbose` is honoured by every npm this project supports and does not
 * change what `npm pack --json` writes to stdout, which is verified below.
 */
function installStderrNoise() {
  fs.writeFileSync(NPMRC, 'loglevel=verbose\n', 'utf8');
}

function restore() {
  fs.writeFileSync(PKG, pkgOriginal, 'utf8');
  if (projectNpmrcOriginal === null) {
    if (fs.existsSync(NPMRC)) fs.unlinkSync(NPMRC);
  } else {
    fs.writeFileSync(NPMRC, projectNpmrcOriginal);
  }
}

/** Point prepublishOnly at a script and run a real dry-run publish. */
function publishWith(prepublishScript, extraEnv = {}) {
  const data = JSON.parse(pkgOriginal);
  data.scripts.prepublishOnly = prepublishScript;
  fs.writeFileSync(PKG, `${JSON.stringify(data, null, 2)}\n`, 'utf8');

  const proc = spawnSync(npmCmd, ['publish', '--dry-run', '--access', 'public'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...extraEnv },
    shell: useShell,
  });
  const stdout = proc.stdout || '';
  return {
    status: proc.status,
    gatePassed: /pre-publish gate: 0 failure\(s\)/.test(stdout),
    failLines: stdout
      .split('\n')
      .filter((l) => l.trim().startsWith('FAIL'))
      .map((l) => l.trim()),
  };
}

try {
  process.stdout.write('=== inside a real dry-run npm publish lifecycle ===\n');

  check('npm writes diagnostics to stderr while stdout holds the payload', () => {
    installStderrNoise();
    const packed = realPack();
    if (packed.stderr.trim() === '') {
      throw new Error(
        'npm produced no stderr, so this environment cannot reproduce the CI condition ' +
          `at all (status=${packed.status}, stdout=${packed.stdout.length} bytes)`,
      );
    }
    // The shape that broke CI: npm succeeded, stdout carried the payload, and
    // diagnostics followed on stderr.
    JSON.parse(packed.stdout);
    process.stdout.write(
      `      reproduced: ${JSON.stringify(packed.stderr.trim().split('\n')[0].slice(0, 70))}\n` +
        `      npm pack itself succeeded: status=${packed.status} ` +
        `tarballs=${packed.tarballs} stdout=${packed.stdout.length} bytes ` +
        `stderr=${packed.stderr.length} bytes\n`,
    );
  });

  check('the gate PASSES inside the publish lifecycle', () => {
    installStderrNoise();
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

  check('the pre-fix parse returns null on this very stream', () => {
    installStderrNoise();
    const packed = realPack();
    // The parser as it was before this fix: stdout concatenated with stderr.
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
    if (oldParse(packed.stdout) === null) {
      throw new Error('stdout did not parse on its own; the environment is unusable');
    }
    if (oldParse(`${packed.stdout}${packed.stderr}`) !== null) {
      throw new Error(
        'the old parse unexpectedly succeeded; stderr was empty, so this run does not ' +
          'reproduce the CI condition and the test proves nothing',
      );
    }
    process.stdout.write('      confirmed: stdout+stderr parse returns null here\n');
  });

  check('the gate passes with npm_config_dry_run in its own environment', () => {
    installStderrNoise();
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
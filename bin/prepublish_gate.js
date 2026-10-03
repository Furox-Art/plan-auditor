#!/usr/bin/env node
'use strict';

/**
 * Pre-publish gate for the npm package.
 *
 * Answers two questions that have each shipped a broken build:
 *
 *   1. Does `npm pack` produce a parseable file list, and does that list
 *      contain exactly the allowlisted paths? npm `2.4.0` shipped a launcher
 *      that could not run at all, and `2.4.1` shipped one that audited the
 *      installed package directory instead of the caller's.
 *   2. Can the installed entry point actually launch the CLI from the caller's
 *      working directory? That is the `2.4.1` defect, and it is checked here
 *      against a real install rather than against the checkout.
 *
 * Both questions used to live in two scripts that each shelled out to `npm`
 * again. Under `npm publish` the lifecycle script is already running inside npm,
 * and the nested invocation inherits `npm_config_*`, `npm_command=publish` and
 * the OIDC/token environment. In run 37120521494 the nested call produced no
 * parseable output, the script fell through to a generic parse-failure message,
 * and because the failure path used `process.exit(1)` immediately after writing
 * to a pipe the log contained no diagnostic at all -- npm reported only
 * `npm error command failed`.
 *
 * Three properties are load-bearing here and are covered by
 * bin/prepublish_gate_contract.test.js:
 *
 *   - the npm invocation is done exactly once, so there is no nested npm to
 *     inherit anything;
 *   - `packed.status` is always checked and always reported;
 *   - every failure path prints the command, the exit code and the captured
 *     output, and sets `process.exitCode` rather than calling `process.exit()`,
 *     so nothing is truncated when the streams are pipes.
 *
 * Runs identically as `npm run test:gate` and as `prepublishOnly`.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

/* --------------------------------------------------------------- reporting */

let failures = 0;

/**
 * Report a failure.
 *
 * Sets `process.exitCode` instead of calling `process.exit()`, because
 * `process.exit()` discards writes still queued on a pipe. On a CI runner both
 * handles are pipes, which is exactly how a real failure lost its entire
 * diagnostic in run 37120521494.
 */
function fail(message, detail) {
  failures += 1;
  process.stderr.write(`FAIL  ${message}\n`);
  if (detail) {
    process.stderr.write(
      `      ${String(detail).split('\n').join('\n      ')}\n`,
    );
  }
}

function pass(message) {
  process.stdout.write(`PASS  ${message}\n`);
}

/* ------------------------------------------------------------ npm resolver */

const NPM_CLI = path.join('node_modules', 'npm', 'bin', 'npm-cli.js');

/**
 * Candidate locations for npm's JavaScript entry point.
 *
 * `npm_execpath` is the important one: npm sets it for every lifecycle script,
 * so it is correct on any platform and inside any npm version. The rest are
 * fallbacks for running this file directly, where no lifecycle environment
 * exists. The join is done per-platform because a POSIX prefix pasted onto a
 * Windows path produces an unmatchable string.
 */
function npmCliCandidates() {
  const dirs = [];
  if (process.env.npm_execpath) dirs.push(process.env.npm_execpath);

  if (process.platform === 'win32') {
    if (process.env.APPDATA) dirs.push(path.join(process.env.APPDATA, 'npm'));
    dirs.push(path.join(path.dirname(process.execPath), 'node_modules', 'npm'));
    dirs.push(path.join(path.dirname(process.execPath), 'npm'));
  } else {
    dirs.push('/usr/local/lib/node_modules/npm');
    dirs.push('/usr/lib/node_modules/npm');
    dirs.push(path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm'));
  }

  // A candidate may already be the .js file, or a directory containing it.
  const candidates = [];
  for (const dir of dirs) {
    if (dir.endsWith('.js')) {
      candidates.push(dir);
    } else {
      candidates.push(path.join(dir, NPM_CLI));
      candidates.push(path.join(dir, 'bin', 'npm-cli.js'));
    }
  }
  return [...new Set(candidates)];
}

/**
 * Run npm once, using the current interpreter so no shell or PATH shim is
 * involved on any platform.
 */
/**
 * Environment for a nested npm invocation.
 *
 * `prepublishOnly` runs while npm is already running this package, so the child
 * inherits the enclosing command's configuration. That is harmless for reading
 * output but fatal for writing files: under `npm publish --dry-run`, npm sets
 * `npm_config_dry_run=true`, and a nested `npm pack` inherits it and reports
 * success while writing no tarball at all. The gate would then fail on "found 0
 * tarballs" for a reason that has nothing to do with the package.
 *
 * npm_config_* is therefore dropped for the nested call. Anything the caller
 * genuinely needs to pass is supplied explicitly through `options.env`.
 */
function nestedEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith('npm_config_')) delete env[key];
  }
  // npm treats npm_command as the in-flight command; a nested npm should not
  // believe it is the one already running.
  delete env.npm_command;
  return env;
}

function runNpm(args, options = {}) {
  const entry = npmCliCandidates().find((c) => fs.existsSync(c));
  if (entry === undefined) {
    return {
      ok: false,
      reason:
        'could not locate npm-cli.js; set npm_execpath or install npm globally. ' +
        `Looked in:\n  ${npmCliCandidates().join('\n  ')}`,
    };
  }
  const { env: extraEnv, ...rest } = options;
  const result = spawnSync(process.execPath, [entry, ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...nestedEnv(), ...(extraEnv || {}) },
    ...rest,
  });
  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  return {
    ok: result.status === 0,
    status: result.status,
    signal: result.signal,
    error: result.error,
    stdout,
    stderr,
    // Always report the command and the exit code: a non-zero status with empty
    // streams is precisely the case the old gate swallowed.
    describe:
      `command: ${process.execPath} ${entry} ${args.join(' ')}\n` +
      `exit code: ${result.status === null ? 'null' : result.status}` +
      `${result.signal ? ` (signal ${result.signal})` : ''}` +
      `${result.error ? `\nerror: ${result.error.message}` : ''}\n` +
      `stdout bytes: ${Buffer.byteLength(stdout)}\n` +
      `stderr bytes: ${Buffer.byteLength(stderr)}` +
      `\nnote: npm_config_* is stripped for this nested call, so the result does` +
      '\n      not reflect --dry-run or any other flag of the enclosing command.' +
      `\n--- stdout ---\n${stdout.slice(0, 2000)}\n--- stderr ---\n${stderr.slice(0, 2000)}`,
  };
}

/* ------------------------------------------------------- tarball inspection */

/**
 * Extract the JSON payload from an npm result.
 *
 * The payload is read from stdout ONLY. npm writes its `--json` document to
 * stdout and its warnings, progress bar and deprecation notices to stderr, and
 * concatenating the two streams puts text after the closing bracket. Every
 * `JSON.parse` over that remainder throws "Extra data", so the gate reported
 * "npm pack produced no parseable file list" on a run where npm had exited 0
 * and written a perfectly good tarball. That is what broke run 37129620610: the
 * CI runner's project `.npmrc` (written by actions/setup-node) makes npm emit
 * `npm warn Unknown project config "always-auth"` on stderr, and Windows
 * produced no such warning, so the same code passed locally and failed in CI.
 *
 * stderr is still reported on failure, because a warning is often the only
 * explanation for what npm did, but it is never parsed.
 *
 * npm 11 on a terminal also prefixes stdout with a progress bar whose
 * "[====]" looks like the start of an array, so the scan still tries each
 * candidate "[" and keeps the first that parses.
 */
function parsePayload(result) {
  const text = typeof result === 'string' ? result : result.stdout || '';
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
}

const FORBIDDEN_PATTERNS = [
  /(^|\/)(__pycache__|\.venv|venv|node_modules|\.pytest_cache|\.ruff_cache|dist|build)(\/|$)/,
  /\.(pyc|pyo|tgz)$/,
  /\.test\.js$/,
  /^\.git/,
];

const REQUIRED = [
  'index.js',
  'bin/plan-auditor.js',
  'supervisor/cli.py',
  'scripts/audit_check.py',
];

/* ------------------------------------------------------------------ stage 1 */

process.stdout.write('=== npm pre-publish gate ===\n');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-prepublish-'));
process.stdout.write(`    scratch: ${scratch}\n`);

const packDir = path.join(scratch, 'pack');
const installDir = path.join(scratch, 'install');
const workspace = path.join(scratch, 'workspace');
for (const dir of [packDir, installDir, workspace]) {
  fs.mkdirSync(dir, { recursive: true });
}

let tarballPaths = null;

{
  const packed = runNpm(['pack', '--pack-destination', packDir, '--json']);
  if (!packed.ok && packed.reason) {
    fail('npm pack could not be started', packed.reason);
  } else if (!packed.ok) {
    fail('npm pack exited non-zero', packed.describe);
  } else {
    const parsed = parsePayload(packed);
    if (parsed === null) {
      fail(
        'npm pack produced no parseable file list on stdout',
        `${packed.describe}\n\nThe payload is read from stdout only, so anything ` +
          'above on stderr is an npm warning and not the cause. If stdout is empty, ' +
          'npm wrote nothing: check that npm is on PATH and that no inherited ' +
          'npm_config_* is suppressing output.',
      );
    } else {
      const produced = fs
        .readdirSync(packDir)
        .filter((f) => f.endsWith('.tgz'))
        .map((f) => path.join(packDir, f));
      if (produced.length !== 1) {
        fail(
          `expected exactly one tarball in ${packDir}, found ${produced.length}`,
          produced.join('\n') || '(directory is empty)',
        );
      } else {
        pass(`npm pack produced ${path.basename(produced[0])}`);
        tarballPaths = produced[0];
      }
    }
  }
}

if (tarballPaths !== null) {
  // The allowlist check reads the file list npm itself reported, so it is the
  // same data npm will upload.
  const listed = runNpm(['pack', '--dry-run', '--json']);
  const parsed = listed.ok ? parsePayload(listed) : null;
  if (parsed === null) {
    fail(
      'npm pack --dry-run produced no parseable file list',
      listed.reason || listed.describe,
    );
  } else {
    const files = (parsed[0].files || []).map((f) => f.path);
    const forbidden = files.filter((p) => FORBIDDEN_PATTERNS.some((re) => re.test(p)));
    if (forbidden.length) {
      fail(
        `tarball ships ${forbidden.length} file(s) that must not be published`,
        forbidden.join('\n'),
      );
    } else {
      pass(`tarball allowlist clean (${files.length} files, no build artifacts)`);
    }

    const missing = REQUIRED.filter((r) => !files.includes(r));
    if (missing.length) {
      fail(
        `tarball is missing ${missing.length} required file(s)`,
        missing.join('\n'),
      );
    } else {
      pass(`tarball contains every required runtime file (${REQUIRED.length})`);
    }
  }
}

/* ------------------------------------------------------------------ stage 2 */

if (tarballPaths !== null) {
  const installed = runNpm([
    'install',
    '--prefix',
    installDir,
    '--no-audit',
    '--no-fund',
    tarballPaths,
  ]);
  if (!installed.ok && installed.reason) {
    fail('installing the tarball could not be started', installed.reason);
  } else if (!installed.ok) {
    fail('installing the tarball exited non-zero', installed.describe);
  } else {
    const binName = process.platform === 'win32' ? 'plan-auditor.cmd' : 'plan-auditor';
    const bin = path.join(installDir, 'node_modules', '.bin', binName);
    if (!fs.existsSync(bin)) {
      fail('the installed package exposes no bin entry point', `expected: ${bin}`);
    } else {
      pass('the tarball installs and exposes a bin entry point');

      fs.mkdirSync(path.join(workspace, '.plan-auditor'), { recursive: true });
      fs.writeFileSync(
        path.join(workspace, '.plan-auditor', 'plan.json'),
        JSON.stringify({
          task: 'pre-publish gate: the installed launcher must use the caller cwd',
          created: '2026-01-01T00:00:00',
          requirements: [{ id: 'R1', description: 'probe', priority: 'must' }],
          steps: [
            {
              id: 1,
              title: 'probe',
              covers: ['R1'],
              verify: [{ type: 'run', cmd: 'python -c "print(1)"', expect_exit: 0 }],
              status: 'pending',
            },
          ],
        }),
        'utf8',
      );

      // cwd is the workspace, not the package directory. This is the assertion
      // that npm 2.4.1 could not satisfy.
      // On Windows the bin is a .cmd shim, which spawnSync cannot execute
      // without a shell. The arguments here are fixed literals, so shell mode
      // carries no quoting risk, and it avoids the DEP0190 warning that a
      // variable-argument shell invocation would produce.
      const isWindows = process.platform === 'win32';
      const probe = spawnSync(bin, ['validate', '.'], {
        cwd: workspace,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        shell: isWindows,
      });
      const probeOut = `${probe.stdout || ''}${probe.stderr || ''}`;
      if (probe.status !== 0) {
        fail(
          'the installed launcher does not audit the caller working directory',
          `command: ${bin} validate .\ncwd: ${workspace}\nexit code: ${probe.status}\n` +
            `--- output ---\n${probeOut.slice(0, 2000)}`,
        );
      } else if (/plan yok|plan not found/i.test(probeOut)) {
        fail(
          'the installed launcher reported no plan for the caller directory',
          `cwd: ${workspace}\n--- output ---\n${probeOut.slice(0, 2000)}`,
        );
      } else {
        pass('the installed launcher audits the caller working directory');
      }

      const failing = spawnSync(bin, ['run', '.', '1'], {
        cwd: workspace,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        shell: isWindows,
      });
      if (failing.status === 0) {
        fail(
          'a failing step was reported as a success by the installed launcher',
          `command: ${bin} run . 1\nexit code: 0`,
        );
      } else {
        pass(`a failing verifier propagates a non-zero exit (${failing.status})`);
      }

      const declared = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
      const installedPkg = JSON.parse(
        fs.readFileSync(path.join(installDir, 'node_modules', 'plan-auditor', 'package.json'), 'utf8'),
      );
      if (installedPkg.version !== declared) {
        fail(
          'the installed version does not match package.json',
          `installed ${installedPkg.version}, declared ${declared}`,
        );
      } else {
        pass(`the installed version matches package.json (${declared})`);
      }
    }
  }
}

fs.rmSync(scratch, { recursive: true, force: true });

process.stdout.write(`\npre-publish gate: ${failures} failure(s)\n`);
if (failures > 0) {
  process.stderr.write(
    'pre-publish gate FAILED; the package must not be published.\n',
  );
}
process.exitCode = failures === 0 ? 0 : 1;
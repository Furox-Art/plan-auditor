#!/usr/bin/env node
'use strict';

/**
 * Assert the packed npm tarball contains only allowlisted files.
 *
 * This runs `npm pack --dry-run --json` itself, so the check cannot be skipped
 * by forgetting a shell redirect, and it parses the output rather than assuming
 * bare JSON: npm writes a progress bar whose "[====]" prefix looks like the
 * start of an array, plus its own npm notice lines, to the same stream.
 *
 * Keeping this in a file rather than an inline `node -e` also means
 * `npm run test:tarball` behaves identically on a developer machine and in CI,
 * which is what caught the inline version failing only in CI.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PACK_ARGS = ['pack', '--dry-run', '--json'];

const packed =
  process.platform === 'win32'
    ? // npm is a .cmd shim on Windows, which spawnSync cannot execute
      // directly. Passing the arguments through cmd.exe would need quoting, so
      // locate the real npm-cli.js and run it with the current interpreter
      // instead: no shell, no quoting, no deprecation warning.
      spawnSync(process.execPath, [npmCliEntry(), ...PACK_ARGS], {
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
      })
    : spawnSync('npm', PACK_ARGS, {
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
      });

/** Resolve npm's JavaScript entry point on Windows. */
function npmCliEntry() {
  const roots = (process.env.APPDATA || '').split(';').filter(Boolean);
  const candidates = [];
  for (const root of roots) {
    candidates.push(`${root}\\npm\\node_modules\\npm\\bin\\npm-cli.js`);
  }
  // A Node installed system-wide or via a version manager.
  candidates.push(
    `${path.dirname(process.execPath)}\\node_modules\\npm\\bin\\npm-cli.js`
  );
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(
    `could not locate npm-cli.js; looked in:\n  ${candidates.join('\n  ')}`
  );
}

if (packed.error) {
  console.error(`could not run npm pack: ${packed.error.message}`);
  process.exit(1);
}

const raw = `${packed.stdout || ''}${packed.stderr || ''}`;

/**
 * Find the JSON array in the captured stream.
 *
 * Trying each "[" and keeping the first candidate that parses as the array we
 * expect is deliberate: the progress bar and notice lines contain bracket
 * characters, so anchoring on the first one picks up garbage.
 */
function parsePayload(text) {
  for (let i = text.indexOf('['); i !== -1; i = text.indexOf('[', i + 1)) {
    // The payload is emitted early; do not scan an unbounded log.
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

const parsed = parsePayload(raw);
if (parsed === null) {
  console.error('could not find the npm pack JSON payload in:\n' + raw.slice(0, 400));
  process.exit(1);
}

const entry = parsed[0];
const paths = (entry.files || []).map((f) => f.path);

const FORBIDDEN_PATTERNS = [
  /(^|\/)(__pycache__|\.venv|venv|node_modules|\.pytest_cache|\.ruff_cache|dist|build)(\/|$)/,
  /\.(pyc|pyo|tgz)$/,
  /\.test\.js$/,
  /^\.git/,
];

const forbidden = paths.filter((p) => FORBIDDEN_PATTERNS.some((re) => re.test(p)));
if (forbidden.length) {
  console.error('tarball ships files that must not be published:');
  for (const p of forbidden) console.error(`  ${p}`);
  process.exit(1);
}

const REQUIRED = [
  'index.js',
  'bin/plan-auditor.js',
  'supervisor/cli.py',
  'scripts/audit_check.py',
];
const missing = REQUIRED.filter((r) => !paths.includes(r));
if (missing.length) {
  console.error('tarball is missing required files:');
  for (const m of missing) console.error(`  ${m}`);
  process.exit(1);
}

console.log(`tarball OK: ${paths.length} files, all allowlisted, no build artifacts`);
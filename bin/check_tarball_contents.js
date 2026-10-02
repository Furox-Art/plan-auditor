#!/usr/bin/env node
'use strict';

/**
 * Assert the packed npm tarball contains only allowlisted files.
 *
 * `npm pack --dry-run --json` writes npm's log lines before the JSON payload,
 * so the output is not parseable as-is. This reads the file, locates the JSON
 * array, and only then validates it. Being a real file (rather than an inline
 * `node -e` blob) also means it is exercised by `npm test` locally.
 */

const fs = require('fs');
const path = require('path');

const packPath = process.argv[2] || 'pack.json';
if (!fs.existsSync(packPath)) {
  console.error(`missing ${packPath}; run "npm pack --dry-run --json > ${packPath}" first`);
  process.exit(1);
}

// Decode encoding-agnostically: a shell redirect can capture the stream as
// UTF-16LE (PowerShell) while bash produces UTF-8, and a BOM would otherwise
// make the payload unparseable.
function readCaptured(file) {
  const buf = fs.readFileSync(file);
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.toString('utf16le').replace(/^﻿/, '');
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.toString('utf8').replace(/^﻿/, '');
  }
  return buf.toString('utf8').replace(/^﻿/, '');
}

const raw = readCaptured(packPath);
const start = raw.indexOf('[');
if (start === -1) {
  console.error('npm pack produced no JSON payload:\n' + raw.slice(0, 400));
  process.exit(1);
}

let parsed;
try {
  parsed = JSON.parse(raw.slice(start));
} catch (err) {
  console.error(`could not parse the npm pack payload: ${err.message}`);
  process.exit(1);
}

const entry = Array.isArray(parsed) ? parsed[0] : parsed;
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

const REQUIRED = ['index.js', 'bin/plan-auditor.js', 'supervisor/cli.py', 'scripts/audit_check.py'];
const missing = REQUIRED.filter((r) => !paths.includes(r));
if (missing.length) {
  console.error('tarball is missing required files:');
  for (const m of missing) console.error(`  ${m}`);
  process.exit(1);
}

console.log(`tarball OK: ${paths.length} files, all allowlisted, no build artifacts`);
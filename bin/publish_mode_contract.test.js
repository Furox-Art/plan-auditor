#!/usr/bin/env node
'use strict';

/**
 * Contract test for the two npm publish modes.
 *
 * `npm-publish.yml` has exactly two modes, and this asserts the property that
 * matters most in each:
 *
 *   oidc   publishes with `--provenance` and no registry token, because the
 *          attestation comes from the OIDC exchange.
 *   token  publishes WITHOUT `--provenance`, because a registry token cannot
 *          mint an attestation. Asking for it would make npm fail the upload.
 *
 * The first real publish attempt on this repository got this wrong: it ran
 * `npm publish --access public --provenance` on Node 20, npm signed the
 * provenance statement and wrote it to the Sigstore transparency log, and the
 * upload was then rejected with E404 because no trusted publisher is registered
 * for this package on npmjs.com. A signature nobody can verify against the
 * package is not an attestation.
 *
 * This reads the workflow and asserts the publish commands, because the command
 * is the whole contract. It does not publish anything.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const WORKFLOW = path.join(ROOT, '.github', 'workflows', 'npm-publish.yml');

let failures = 0;

function check(name, fn) {
  try {
    fn();
    process.stdout.write(`  PASS  ${name}\n`);
  } catch (err) {
    failures += 1;
    process.stdout.write(`  FAIL  ${name}\n        ${err.message}\n`);
  }
}

const text = fs.existsSync(WORKFLOW) ? fs.readFileSync(WORKFLOW, 'utf8') : '';

/** Every `npm publish ...` invocation in the workflow, however it is written. */
function publishCommands() {
  return text
    .split('\n')
    .map((line) => line.trim())
    // Match the command itself, not the `run:` key that introduces it.
    .flatMap((line) => {
      // Case-sensitive lowercase, so the workflow's own `name: npm Publish` header
      // is not mistaken for a command.
      const match = /npm publish [^\n"']*/.exec(line);
      return match ? [match[0].trim()] : [];
    })
    .map((cmd) => ({
      raw: cmd,
      hasProvenance: cmd.includes('--provenance'),
      hasAccessPublic: cmd.includes('--access public'),
    }));
}

/** The `if:` condition guarding a named step. */
function stepCondition(stepName) {
  const lines = text.split('\n');
  const index = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  if (index === -1) return null;
  for (let i = index + 1; i < Math.min(index + 6, lines.length); i += 1) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('if:')) return trimmed.slice(3).trim();
    if (trimmed.startsWith('- name:') || trimmed.startsWith('- uses:')) break;
  }
  return null;
}

const commands = publishCommands();

check('the workflow defines a workflow_dispatch input for token mode', () => {
  assert_match(text, /use_token_fallback:/, 'no use_token_fallback input declared');
  assert_match(text, /type:\s*boolean/, 'use_token_fallback is not a boolean');
  assert_match(text, /default:\s*false/, 'use_token_fallback does not default to false');
});

check('there are exactly two npm publish commands, one per mode', () => {
  if (commands.length !== 2) {
    throw new Error(
      `expected 2 npm publish commands (oidc + token), found ${commands.length}: ` +
        commands.map((c) => c.raw).join(' | ')
    );
  }
});

check('the OIDC path publishes with --provenance', () => {
  const withProvenance = commands.filter((c) => c.hasProvenance);
  if (withProvenance.length !== 1) {
    throw new Error(`expected exactly one publish with --provenance, found ${withProvenance.length}`);
  }
  if (!withProvenance[0].raw.includes('--access public')) {
    throw new Error(`the provenance publish is missing --access public: ${withProvenance[0].raw}`);
  }
});

check('the token path does NOT request --provenance', () => {
  const withoutProvenance = commands.filter((c) => !c.hasProvenance);
  if (withoutProvenance.length !== 1) {
    throw new Error(`expected exactly one publish without --provenance, found ${withoutProvenance.length}`);
  }
  const cmd = withoutProvenance[0].raw;
  if (cmd.includes('--provenance')) {
    throw new Error(`token publish must not ask for an attestation: ${cmd}`);
  }
  if (!cmd.includes('--access public')) {
    throw new Error(`the token publish is missing --access public: ${cmd}`);
  }
});

check('both publish commands are guarded by the version-existence gate', () => {
  for (const step of ['Publish to npm with trusted publishing', 'Publish to npm with the NPM_TOKEN secret']) {
    const condition = stepCondition(step);
    if (condition === null) throw new Error(`step "${step}" has no if: condition`);
    if (!condition.includes(`steps.gate.outputs.skip != 'true'`)) {
      throw new Error(`step "${step}" is not guarded by the version gate: ${condition}`);
    }
  }
});

check('each publish command is gated on exactly one mode', () => {
  const oidc = stepCondition('Publish to npm with trusted publishing');
  const token = stepCondition('Publish to npm with the NPM_TOKEN secret');
  if (!oidc.includes(`steps.mode.outputs.mode == 'oidc'`)) {
    throw new Error(`the provenance publish is not gated on the oidc mode: ${oidc}`);
  }
  if (!token.includes(`steps.mode.outputs.mode == 'token'`)) {
    throw new Error(`the token publish is not gated on the token mode: ${token}`);
  }
});

check('the token mode fails closed when NPM_TOKEN is absent', () => {
  assert_match(
    text,
    /if \[ -z "\$NODE_AUTH_TOKEN" \]/,
    'token mode does not check for an empty NPM_TOKEN',
  );
  assert_match(
    text,
    /::error::use_token_fallback was requested but the NPM_TOKEN secret is empty/,
    'token mode has no actionable error when the secret is missing',
  );
});

check('the token path is opt-in, never an automatic fallback', () => {
  // A publish step keyed on `steps.trusted_publish.outcome != 'success'` would
  // silently downgrade to an unattested upload whenever trusted publishing
  // failed for any reason. That is the behaviour this asserts against.
  if (/steps\.trusted_publish\.outcome/.test(text)) {
    throw new Error(
      'a publish step still keys on trusted_publish.outcome, which re-enables ' +
        'the automatic token fallback',
    );
  }
  assert_match(
    text,
    /use_token_fallback was requested/,
    'the token path does not state that it requires the explicit opt-in',
  );
});

check('both jobs run on Node 24', () => {
  const nodeVersions = [...text.matchAll(/node-version:\s*"([^"]+)"/g)].map((m) => m[1]);
  if (nodeVersions.length === 0) throw new Error('no node-version found');
  const bad = nodeVersions.filter((v) => Number.parseInt(v, 10) < 24);
  if (bad.length) {
    throw new Error(
      `node-version below 24 found: ${bad.join(', ')}. npm 10.x on Node 20 ` +
        'cannot do trusted publishing or provenance',
    );
  }
});

check('the npm floor is checked numerically, not by regex', () => {
  if (/node -e '\s*.*\^1[12]\./s.test(text)) {
    throw new Error('the npm version floor still looks like a regex');
  }
  assert_match(text, /const MIN = \[11, 5, 1\]/, 'no numeric npm floor found');
  assert_match(text, /major > MIN\[0\]/, 'the npm floor is not a numeric comparison');
});

check('every existing release gate survives', () => {
  assert_match(text, /npm view "plan-auditor@\$\{\{ steps\.meta\.outputs\.version \}\}"/,
    'the registry version-existence check is gone');
  assert_match(text, /check_version_lockstep\.py/, 'the version lockstep check is gone');
  assert_match(text, /test:tarball/, 'the tarball allowlist check is gone');
  assert_match(text, /test:installed/, 'the installed-launcher verification is gone');
});

function assert_match(haystack, pattern, message) {
  const re = pattern instanceof RegExp ? pattern : new RegExp(pattern);
  if (!re.test(haystack)) throw new Error(message);
}

process.stdout.write(`\npublish-mode contract: ${failures} failure(s)\n`);
process.exit(failures === 0 ? 0 : 1);
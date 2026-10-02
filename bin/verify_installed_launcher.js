#!/usr/bin/env node
'use strict';

/**
 * Prove the *installed* npm tarball launches the CLI from the caller's cwd.
 *
 * Two published npm builds were defective in ways no existing gate caught:
 *
 *   2.4.0  shipped a JavaScript syntax error, so `npx plan-auditor` could not
 *          run at all.
 *   2.4.1  shipped a working launcher that passed `cwd: __dirname` to spawn, so
 *          a relative workspace path resolved against the installed package
 *          directory. `plan-auditor validate .` from a real workspace reported
 *          "plan yok: .../node_modules/plan-auditor/.plan-auditor/plan.json"
 *          while looking like an authoritative answer.
 *
 * This installs the packed tarball into a throwaway directory and runs the
 * installed bin from an unrelated working directory. Anything that hard-codes
 * the package directory as cwd fails here, and so does a launcher that cannot
 * start. Run before every publish.
 *
 *   node bin/verify_installed_launcher.js
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const sh = process.platform === 'win32' ? 'cmd' : 'sh';
const shFlag = process.platform === 'win32' ? '/d /s /c' : '-c';

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

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-npm-verify-'));
const installDir = path.join(root, 'install');
const workspace = path.join(root, 'workspace');

process.stdout.write(`=== verifying the installed npm tarball ===\n`);
process.stdout.write(`    scratch: ${root}\n`);

/* ---------------------------------------------------------------- pack */

const packDir = path.join(root, 'pack');
fs.mkdirSync(packDir, { recursive: true });

const packed = run(npmCmd, ['pack', '--pack-destination', packDir], {
  cwd: path.resolve(__dirname, '..'),
  shell: process.platform === 'win32',
});
if (packed.status !== 0) {
  console.error('npm pack failed:\n' + (packed.stdout || '') + (packed.stderr || ''));
  process.exit(1);
}

const tarball = fs
  .readdirSync(packDir)
  .filter((f) => f.endsWith('.tgz'))
  .map((f) => path.join(packDir, f));
if (tarball.length !== 1) {
  console.error(`expected exactly one tarball, found ${tarball.length}`);
  process.exit(1);
}
process.stdout.write(`    tarball: ${path.basename(tarball[0])}\n`);

/* ------------------------------------------------------------- install */

fs.mkdirSync(installDir, { recursive: true });
const installed = run(
  npmCmd,
  ['install', '--prefix', installDir, '--no-audit', '--no-fund', tarball[0]],
  { shell: process.platform === 'win32' },
);
if (installed.status !== 0) {
  console.error('npm install of the tarball failed:\n' + (installed.stdout || '') + (installed.stderr || ''));
  process.exit(1);
}

/* ------------------------------------------------------------ workspace */

fs.mkdirSync(path.join(workspace, '.plan-auditor'), { recursive: true });
fs.writeFileSync(
  path.join(workspace, '.plan-auditor', 'plan.json'),
  JSON.stringify(
    {
      task: 'installed launcher must audit the caller working directory',
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
    },
    null,
    2,
  ),
  'utf8',
);

/* ----------------------------------------------------------------- run */

const binName = process.platform === 'win32' ? 'plan-auditor.cmd' : 'plan-auditor';
const installedBin = path.join(installDir, 'node_modules', '.bin', binName);

check('the packed tarball installs and produces a bin entry point', () => {
  if (!fs.existsSync(installedBin)) {
    throw new Error(`installed bin missing at ${installedBin}`);
  }
});

check('the installed launcher runs the CLI from the caller working directory', () => {
  // cwd is the workspace; the package lives elsewhere. A launcher that hard-codes
  // its own directory as cwd resolves "." against the package and finds no plan.
  const result = run(installedBin, ['validate', '.'], { cwd: workspace, shell: process.platform === 'win32' });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  if (result.status !== 0) {
    throw new Error(
      `validate . exited ${result.status} from ${workspace}.\n` +
        `output: ${output.trim().slice(0, 500)}`
    );
  }
  // The 2.4.1 defect produced exit 1 with "plan yok" pointing at the package
  // directory. Guard against a launcher that merely happens to exit 0.
  if (/plan yok|plan not found/i.test(output)) {
    throw new Error(`launcher reported no plan for the caller's directory:\n${output.trim()}`);
  }
});

check('the installed launcher resolves an absolute workspace path too', () => {
  const result = run(installedBin, ['validate', workspace], {
    cwd: root,
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(
      `validate <abs> exited ${result.status}.\n` +
        `output: ${`${result.stdout || ''}${result.stderr || ''}`.trim().slice(0, 500)}`
    );
  }
});

check('the installed launcher propagates a failing verifier exit code', () => {
  // Step 1 expects exit 0 but the command exits 3, so `run` must fail.
  const result = run(installedBin, ['run', '.', '1'], {
    cwd: workspace,
    shell: process.platform === 'win32',
  });
  if (result.status === 0) {
    throw new Error('a failing step was reported as a success by the installed launcher');
  }
});

check('the installed launcher is the version package.json declares', () => {
  const declared = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'),
  ).version;
  const installedPkg = JSON.parse(
    fs.readFileSync(path.join(installDir, 'node_modules', 'plan-auditor', 'package.json'), 'utf8'),
  );
  if (installedPkg.version !== declared) {
    throw new Error(
      `installed ${installedPkg.version} does not match declared ${declared}`,
    );
  }
});

fs.rmSync(root, { recursive: true, force: true });

process.stdout.write(
  `\ninstalled-launcher verification: ${failures} failure(s)\n`,
);
process.exit(failures === 0 ? 0 : 1);
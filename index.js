const { spawn } = require('child_process');
const path = require('path');

const FAILURE_EXIT_CODE = 1;

function pythonExecutable() {
  return process.platform === 'win32' ? 'python' : 'python3';
}

/**
 * Build the child environment.
 *
 * The installed npm package carries its own copy of `supervisor/` next to this
 * file, so that directory has to be importable. Prepending it to PYTHONPATH
 * does that without changing the working directory, which matters because the
 * workspace path the user passed (often a bare ".") must resolve against the
 * directory they invoked the command from, not against the package location.
 *
 * An existing PYTHONPATH is preserved rather than replaced.
 */
function childEnv() {
  const existing = process.env.PYTHONPATH;
  const packageRoot = __dirname;
  return {
    ...process.env,
    PYTHONPATH: existing ? `${packageRoot}${path.delimiter}${existing}` : packageRoot,
  };
}

function runPython(args) {
  return spawn(pythonExecutable(), ['-m', 'supervisor.cli', ...args], {
    stdio: 'inherit',
    cwd: process.cwd(),
    env: childEnv(),
  });
}

/**
 * Run the CLI and mirror its exit code onto this process.
 *
 * The verifier's exit code is the only trustworthy verdict it produces, so no
 * entry point may turn a FAIL into a success. Returns the child so callers can
 * observe it; the handlers are attached here so every caller gets them.
 */
function runPythonAndPropagate(args) {
  const child = runPython(args);
  child.on('error', (err) => {
    console.error(`plan-auditor: failed to start Python: ${err.message}`);
    process.exit(FAILURE_EXIT_CODE);
  });
  child.on('close', (code) => {
    process.exit(code === null ? FAILURE_EXIT_CODE : code);
  });
  return child;
}

module.exports = { runPython, runPythonAndPropagate };

if (require.main === module) {
  runPythonAndPropagate(process.argv.slice(2));
}
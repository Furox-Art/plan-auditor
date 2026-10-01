const { spawn } = require('child_process');

const FAILURE_EXIT_CODE = 1;

function runPython(args) {
  const python = process.platform === 'win32' ? 'python' : 'python3';
  return spawn(python, ['-m', 'supervisor.cli', ...args], {
    stdio: 'inherit',
    cwd: __dirname,
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
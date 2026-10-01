const { spawn } = require('child_process');

const FAILURE_EXIT_CODE = 1;

function runPython(args) {
  const python = process.platform === 'win32' ? 'python' : 'python3';
  return spawn(python, ['-m', 'supervisor.cli', ...args], {
    stdio: 'inherit',
    cwd: __dirname,
  });
}

module.exports = { runPython };

if (require.main === module) {
  const child = runPython(process.argv.slice(2));
  // The verifier's exit code is the only trustworthy verdict it produces, so the
  // launcher must not turn a FAIL into a success.
  child.on('error', (err) => {
    console.error(`plan-auditor: failed to start Python: ${err.message}`);
    process.exit(FAILURE_EXIT_CODE);
  });
  child.on('close', (code) => {
    process.exit(code === null ? FAILURE_EXIT_CODE : code);
  });
}
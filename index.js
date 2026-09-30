const { spawn } = require('child_process');

function runPython(args) {
  const python = process.platform === 'win32' ? 'python' : 'python3';
  return spawn(python, ['-m', 'supervisor.cli', ...args], {
    stdio: 'inherit',
    cwd: __dirname,
  });
}

module.exports = { runPython };

if (require.main === module) {
  runPython(process.argv.slice(2));
}
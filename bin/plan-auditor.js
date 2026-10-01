#!/usr/bin/env node
// This file is what `npx plan-auditor` and the `bin` field in package.json
// resolve to, so the exit-code propagation has to happen here. runPython() alone
// only spawns the child; without attaching the handlers a failing audit exits 0.
require('../index.js').runPythonAndPropagate(process.argv.slice(2));
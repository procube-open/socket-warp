#!/usr/bin/env node
const { spawn } = require('node:child_process');
const p = spawn(__dirname + '/../cs/start-pr.sh', process.argv.slice(2), {stdio: 'inherit'});
p.on('close', (code) => process.exit(code))
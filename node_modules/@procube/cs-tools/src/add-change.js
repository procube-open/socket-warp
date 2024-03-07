#!/usr/bin/env node
const { spawn } = require('node:child_process');
const p = spawn(__dirname + '/../cs/add-change.sh',  process.argv.slice(2), {stdio: 'inherit'});
p.on('close', (code) => process.exit(code))
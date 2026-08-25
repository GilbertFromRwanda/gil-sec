#!/usr/bin/env node
// Installs gil-sec as an auto-start entry appropriate for the current OS:
// Windows -> Scheduled Task, macOS -> launchd agent, Linux -> systemd user service.

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const projectDir = path.resolve(__dirname, '..');

function findPnpm() {
  const cmd = process.platform === 'win32' ? 'where pnpm' : 'command -v pnpm';
  const out = execSync(cmd, { encoding: 'utf8' }).trim().split('\n')[0].trim();
  if (!out) throw new Error('Could not locate the pnpm executable on PATH');
  return out;
}

function installWindows() {
  const script = path.join(__dirname, 'register-startup-task.ps1');
  execSync(`powershell -ExecutionPolicy Bypass -File "${script}"`, { stdio: 'inherit' });
}

function installMac() {
  const pnpm = findPnpm();
  const plistPath = path.join(os.homedir(), 'Library/LaunchAgents/com.gilsec.monitor.plist');
  const template = fs.readFileSync(path.join(__dirname, 'startup/com.gilsec.monitor.plist'), 'utf8');
  const content = template.replaceAll('%PNPM%', pnpm).replaceAll('%WORKDIR%', projectDir);

  fs.mkdirSync(path.dirname(plistPath), { recursive: true });
  fs.writeFileSync(plistPath, content);

  try {
    execSync(`launchctl unload "${plistPath}"`, { stdio: 'ignore' });
  } catch {
    // not previously loaded — fine
  }
  execSync(`launchctl load -w "${plistPath}"`, { stdio: 'inherit' });

  console.log(`Installed launchd agent at ${plistPath}`);
  console.log('It will start at next login, and it just started now via launchctl load.');
}

function installLinux() {
  const pnpm = findPnpm();
  const unitDir = path.join(os.homedir(), '.config/systemd/user');
  const unitPath = path.join(unitDir, 'gil-sec.service');
  const template = fs.readFileSync(path.join(__dirname, 'startup/gil-sec.service'), 'utf8');
  const content = template.replaceAll('%PNPM%', pnpm).replaceAll('%WORKDIR%', projectDir);

  fs.mkdirSync(unitDir, { recursive: true });
  fs.writeFileSync(unitPath, content);

  execSync('systemctl --user daemon-reload', { stdio: 'inherit' });
  execSync('systemctl --user enable --now gil-sec.service', { stdio: 'inherit' });

  console.log(`Installed systemd user service at ${unitPath}`);
  console.log('Tip: run "loginctl enable-linger $USER" to keep it running after you log out.');
}

switch (process.platform) {
  case 'win32':
    installWindows();
    break;
  case 'darwin':
    installMac();
    break;
  case 'linux':
    installLinux();
    break;
  default:
    console.error(`Unsupported platform: ${process.platform}`);
    process.exit(1);
}

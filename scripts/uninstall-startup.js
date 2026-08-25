#!/usr/bin/env node
// Reverses whatever install-startup.js set up for the current OS.

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function uninstallWindows() {
  const script = path.join(__dirname, 'unregister-startup-task.ps1');
  execSync(`powershell -ExecutionPolicy Bypass -File "${script}"`, { stdio: 'inherit' });
}

function uninstallMac() {
  const plistPath = path.join(os.homedir(), 'Library/LaunchAgents/com.gilsec.monitor.plist');
  if (!fs.existsSync(plistPath)) {
    console.log('No launchd agent installed.');
    return;
  }
  execSync(`launchctl unload "${plistPath}"`, { stdio: 'inherit' });
  fs.unlinkSync(plistPath);
  console.log('Removed launchd agent.');
}

function uninstallLinux() {
  const unitPath = path.join(os.homedir(), '.config/systemd/user/gil-sec.service');
  if (!fs.existsSync(unitPath)) {
    console.log('No systemd user service installed.');
    return;
  }
  execSync('systemctl --user disable --now gil-sec.service', { stdio: 'inherit' });
  fs.unlinkSync(unitPath);
  execSync('systemctl --user daemon-reload', { stdio: 'inherit' });
  console.log('Removed systemd user service.');
}

switch (process.platform) {
  case 'win32':
    uninstallWindows();
    break;
  case 'darwin':
    uninstallMac();
    break;
  case 'linux':
    uninstallLinux();
    break;
  default:
    console.error(`Unsupported platform: ${process.platform}`);
    process.exit(1);
}

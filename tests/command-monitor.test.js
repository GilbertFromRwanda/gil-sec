const childProcess = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { CommandMonitor } = require('../monitor/command-monitor');

describe('CommandMonitor', () => {
  let monitor;
  const logFile = path.join(os.tmpdir(), `gil-sec-cmd-test-${Date.now()}.log`);

  beforeAll(() => {
    monitor = new CommandMonitor({ logFile, alert: false });
  });

  afterAll(() => {
    monitor.restore();
    monitor.logger.stopFlushTimer();
    monitor.logger.flush();
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  });

  test('analyzeCommand blocks a dangerous command', () => {
    const result = monitor.analyzeCommand('rm', ['-rf', '/tmp/test'], 'exec');
    expect(result.blocked).toBe(true);
  });

  test('analyzeCommand allows a benign command', () => {
    const result = monitor.analyzeCommand('git', ['status'], 'exec');
    expect(result.blocked).toBe(false);
  });

  test('getStats reflects intercepted/blocked counts', () => {
    const stats = monitor.getStats();
    expect(stats.intercepted).toBeGreaterThanOrEqual(2);
    expect(stats.blocked).toBeGreaterThanOrEqual(1);
  });

  test('hooked child_process.exec throws for dangerous commands', () => {
    expect(() => childProcess.exec('rm -rf /tmp/whatever')).toThrow(/SECURITY/);
  });

  test('hooked child_process.exec passes an error to the callback instead of throwing when one is given', done => {
    childProcess.exec('rm -rf /tmp/whatever', {}, (err) => {
      expect(err).toBeTruthy();
      expect(err.code).toBe('SECURITY_BLOCK');
      done();
    });
  });

  test('hooked child_process.spawn throws for dangerous commands', () => {
    expect(() => childProcess.spawn('chmod', ['777', '/etc/passwd'])).toThrow(/SECURITY/);
  });

  test('restore() puts back the original child_process methods', () => {
    const originalExec = monitor.originalExec;
    monitor.restore();
    expect(childProcess.exec).toBe(originalExec);
  });
});

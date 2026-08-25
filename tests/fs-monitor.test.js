const path = require('path');
const os = require('os');
const { FSMonitor } = require('../monitor/fs-monitor');

describe('FSMonitor', () => {
  let monitor;
  const logFile = path.join(os.tmpdir(), `gil-sec-fs-test-${Date.now()}.log`);

  beforeAll(() => {
    monitor = new FSMonitor({
      logFile,
      protectedPaths: ['/etc', '/bin'],
      allowedExtensions: ['.txt', '.log']
    });
  });

  afterAll(() => {
    monitor.logger.stopFlushTimer();
    monitor.logger.flush();
    const fs = require('fs');
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  });

  test('blocks operations on protected paths with disallowed extensions', () => {
    const result = monitor.checkPath('/etc/passwd', 'unlink');
    expect(result.blocked).toBe(true);
    expect(result.isProtected).toBe(true);
  });

  test('allows protected-path operations when extension is allowlisted', () => {
    const result = monitor.checkPath('/etc/app.log', 'writeFile');
    expect(result.blocked).toBe(false);
    expect(result.isProtected).toBe(true);
    expect(result.isAllowed).toBe(true);
  });

  test('allows operations outside protected paths', () => {
    const result = monitor.checkPath('/home/user/project/file.js', 'writeFile');
    expect(result.blocked).toBe(false);
    expect(result.isProtected).toBe(false);
  });

  test('addProtectedPath extends protection to new paths', () => {
    monitor.addProtectedPath('/opt/secrets');
    const result = monitor.checkPath('/opt/secrets/key.pem', 'unlink');
    expect(result.blocked).toBe(true);
  });

  test('removeProtectedPath lifts protection from a path', () => {
    monitor.addProtectedPath('/opt/scratch');
    monitor.removeProtectedPath('/opt/scratch');
    const result = monitor.checkPath('/opt/scratch/file.bin', 'unlink');
    expect(result.isProtected).toBe(false);
  });

  test('getStats tracks intercepted/blocked/allowed counts', () => {
    const stats = monitor.getStats();
    expect(stats.intercepted).toBeGreaterThan(0);
    expect(stats.intercepted).toBe(stats.blocked + stats.allowed);
  });
});

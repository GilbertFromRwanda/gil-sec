const path = require('path');
const os = require('os');
const fs = require('fs');
const { NetworkMonitor } = require('../monitor/network-monitor');

describe('NetworkMonitor', () => {
  let monitor;
  const logFile = path.join(os.tmpdir(), `gil-sec-net-test-${Date.now()}.log`);

  beforeAll(() => {
    monitor = new NetworkMonitor({ logFile, blocklist: ['evil.example.com'] });
  });

  afterAll(() => {
    monitor.logger.stopFlushTimer();
    monitor.logger.flush();
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  });

  test('blocks connections to a blocklisted host', () => {
    const result = monitor.checkConnection('evil.example.com', 443);
    expect(result.blocked).toBe(true);
  });

  test('blocks connections to known Ethereum RPC endpoints by default', () => {
    const defaultLogFile = path.join(os.tmpdir(), `gil-sec-net-default-${Date.now()}.log`);
    const defaultMonitor = new NetworkMonitor({ logFile: defaultLogFile });

    expect(defaultMonitor.checkConnection('mainnet.infura.io', 443).blocked).toBe(true);
    expect(defaultMonitor.checkConnection('cloudflare-eth.com', 443).blocked).toBe(true);
    expect(defaultMonitor.checkConnection('eth-mainnet.publicnode.com', 443).blocked).toBe(true);
    expect(defaultMonitor.checkConnection('ethereum-rpc.publicnode.com', 443).blocked).toBe(true);

    defaultMonitor.logger.stopFlushTimer();
    defaultMonitor.logger.flush();
    if (fs.existsSync(defaultLogFile)) fs.unlinkSync(defaultLogFile);
  });

  test('blocks connections to suspicious ports', () => {
    const result = monitor.checkConnection('example.com', 3389);
    expect(result.blocked).toBe(true);
  });

  test('allows connections to safe hosts and ports', () => {
    const result = monitor.checkConnection('example.com', 443);
    expect(result.blocked).toBe(false);
  });

  test('allowlisted hosts bypass the blocklist and suspicious ports', () => {
    monitor.allowlist.push('evil.example.com');
    const result = monitor.checkConnection('evil.example.com', 3389);
    expect(result.blocked).toBe(false);
    expect(result.reason).toBe('Allowed host');
  });

  test('flags known suspicious TLDs as suspicious hostnames', () => {
    expect(monitor.checkHostname('malicious.onion')).toBe(true);
    expect(monitor.checkHostname('example.com')).toBe(false);
  });

  test('addBlocklist adds a host without duplicating it', () => {
    monitor.addBlocklist('bad.example.com');
    monitor.addBlocklist('bad.example.com');
    expect(monitor.blocklist.filter(h => h === 'bad.example.com')).toHaveLength(1);
  });

  test('checkPayload detects a GitHub token', () => {
    const findings = monitor.checkPayload('token=ghp_1234567890abcdef1234567890abcdef1234');
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('GitHub Token');
    expect(findings[0].masked).toBe('ghp_...1234');
  });

  test('checkPayload detects an AWS access key', () => {
    const findings = monitor.checkPayload('AWS_KEY=AKIAABCDEFGHIJKLMNOP');
    expect(findings.some(f => f.type === 'AWS Access Key')).toBe(true);
  });

  test('checkPayload allows a GitHub token sent to github.com', () => {
    const findings = monitor.checkPayload('token=ghp_1234567890abcdef1234567890abcdef1234', 'github.com');
    expect(findings).toHaveLength(0);
  });

  test('checkPayload allows a GitHub token sent to a github.com subdomain', () => {
    const findings = monitor.checkPayload('token=ghp_1234567890abcdef1234567890abcdef1234', 'api.github.com');
    expect(findings).toHaveLength(0);
  });

  test('checkPayload still flags a GitHub token sent to a non-GitHub host', () => {
    const findings = monitor.checkPayload('token=ghp_1234567890abcdef1234567890abcdef1234', 'evil.example.com');
    expect(findings).toHaveLength(1);
  });

  test('checkPayload does not let a lookalike host bypass detection', () => {
    const findings = monitor.checkPayload('token=ghp_1234567890abcdef1234567890abcdef1234', 'github.com.evil.example.com');
    expect(findings).toHaveLength(1);
  });

  test('checkPayload returns nothing for ordinary payloads', () => {
    expect(monitor.checkPayload('{"jsonrpc":"2.0","method":"eth_blockNumber"}')).toHaveLength(0);
  });

  test('checkPayload handles Buffer input', () => {
    const findings = monitor.checkPayload(Buffer.from('ghp_1234567890abcdef1234567890abcdef1234'));
    expect(findings).toHaveLength(1);
  });

  test('hooked socket.write blocks a payload containing a GitHub token', () => {
    const net = require('net');
    const socket = new net.Socket();
    socket.on('error', () => {}); // avoid unhandled 'error' from the never-connected socket
    socket._gilSecHost = 'example.com';
    socket._gilSecPort = 443;

    expect(() => socket.write('token=ghp_1234567890abcdef1234567890abcdef1234'))
      .toThrow(/SECURITY/);

    socket.destroy();
  });

  test('hooked socket.write allows a GitHub token sent to github.com', () => {
    const net = require('net');
    const socket = new net.Socket();
    socket.on('error', () => {});
    socket._gilSecHost = 'api.github.com';
    socket._gilSecPort = 443;

    expect(() => socket.write('token=ghp_1234567890abcdef1234567890abcdef1234')).not.toThrow();

    socket.destroy();
  });

  test('hooked socket.write allows payloads with no secrets', () => {
    const net = require('net');
    const socket = new net.Socket();
    socket.on('error', () => {});
    socket._gilSecHost = 'example.com';
    socket._gilSecPort = 443;

    expect(() => socket.write('{"jsonrpc":"2.0","method":"eth_blockNumber"}')).not.toThrow();

    socket.destroy();
  });

  test('getStats tracks outgoing/blocked/allowed counts', () => {
    const stats = monitor.getStats();
    expect(stats.outgoing).toBeGreaterThan(0);
    expect(stats.outgoing).toBe(stats.blocked + stats.allowed);
  });
});

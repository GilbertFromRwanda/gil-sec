const net = require('net');
const dns = require('dns');
const { Logger } = require('./logger');

class NetworkMonitor {
  constructor(options = {}) {
    this.logger = new Logger(options.logFile || './security.log');
    this.blocklist = options.blocklist || [
      '127.0.0.1', 'localhost', '0.0.0.0',
      '::1', '::',
      // Known Ethereum RPC endpoints, commonly abused by malicious packages
      // to fingerprint or drain wallets
      'eth-mainnet.publicnode.com',
      'ethereum-rpc.publicnode.com',
      'cloudflare-eth.com',
      'mainnet.infura.io'
    ];
    this.allowlist = options.allowlist || [];
    this.suspiciousPorts = [22, 23, 445, 3389, 5432, 3306, 27017];

    // Patterns for credentials that should never leave the machine in an
    // outgoing request body, regardless of destination
    // trustedHosts: destinations where this credential is expected to be
    // sent as part of normal, legitimate use (e.g. a GitHub token going to
    // GitHub itself). Only flag the secret when it's headed elsewhere.
    this.secretPatterns = options.secretPatterns || [
      { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36,255}/g, trustedHosts: ['github.com', 'githubusercontent.com'] },
      { name: 'GitHub Fine-Grained PAT', pattern: /github_pat_[A-Za-z0-9_]{22,}/g, trustedHosts: ['github.com', 'githubusercontent.com'] },
      { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, trustedHosts: ['amazonaws.com'] },
      { name: 'Authorization Bearer Token', pattern: /Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)/gi, group: 1 }
    ];

    this.hookMethods();
    this.stats = {
      outgoing: 0,
      blocked: 0,
      allowed: 0
    };
  }

  hookMethods() {
    // Hook net.Socket.connect
    const originalConnect = net.Socket.prototype.connect;
    const self = this;

    net.Socket.prototype.connect = function(...args) {
      let options = args[0];
      let port, host;

      // Parse different argument patterns
      if (typeof options === 'object') {
        port = options.port;
        host = options.host || 'localhost';
      } else if (typeof options === 'number') {
        port = options;
        host = args[1] || 'localhost';
      } else {
        port = 80;
        host = 'localhost';
      }

      const result = self.checkConnection(host, port);

      if (result.blocked) {
        const error = new Error(`[SECURITY] Connection blocked to ${host}:${port}`);
        error.code = 'SECURITY_BLOCK';
        throw error;
      }

      // Remember the destination so the write() hook can report it if a
      // secret shows up in the payload later
      this._gilSecHost = host;
      this._gilSecPort = port;

      return originalConnect.call(this, ...args);
    };

    // Hook net.Socket.write to catch credentials in outgoing payloads,
    // regardless of which host they're headed to
    const originalWrite = net.Socket.prototype.write;

    net.Socket.prototype.write = function(chunk, encoding, callback) {
      const host = this._gilSecHost || this.remoteAddress || 'unknown';
      const port = this._gilSecPort || this.remotePort;
      const findings = self.checkPayload(chunk, host);

      if (findings.length > 0) {
        self.stats.blocked++;
        self.logger.log({
          timestamp: new Date().toISOString(),
          type: 'network-payload',
          host,
          port,
          result: { blocked: true, findings },
          stack: new Error().stack,
          pid: process.pid
        });

        console.warn(`[EXFIL-BLOCKED] Outgoing payload to ${host}:${port} contained: ${findings.map(f => f.type).join(', ')}`);
        findings.forEach(f => console.warn(`  -> ${f.type}: ${f.masked}`));

        const error = new Error(`[SECURITY] Blocked outgoing payload containing: ${findings.map(f => f.type).join(', ')}`);
        error.code = 'SECURITY_BLOCK';
        error.details = { findings, host, port };

        const cb = [callback, encoding].find(a => typeof a === 'function');
        if (cb) {
          cb(error);
          return false;
        }
        throw error;
      }

      return originalWrite.call(this, chunk, encoding, callback);
    };

    // Hook DNS resolve
    const originalResolve = dns.resolve;
    dns.resolve = (hostname, rrtype, callback) => {
      // Check if hostname is suspicious
      const isSuspicious = this.checkHostname(hostname);
      
      if (isSuspicious) {
        this.logger.log({
          timestamp: new Date().toISOString(),
          type: 'dns',
          hostname: hostname,
          result: { blocked: true, reason: 'Suspicious hostname' },
          pid: process.pid
        });
        
        console.warn(`[DNS-BLOCKED] ${hostname}`);
        
        if (typeof callback === 'function') {
          const error = new Error(`DNS lookup blocked: ${hostname}`);
          error.code = 'SECURITY_BLOCK';
          return callback(error, null);
        }
      }
      
      return originalResolve.call(this, hostname, rrtype, callback);
    };

    console.log('[Monitor] Network monitoring active');
  }

  checkConnection(host, port) {
    this.stats.outgoing++;
    
    // Check allowlist first
    if (this.allowlist.includes(host)) {
      this.stats.allowed++;
      return { blocked: false, reason: 'Allowed host' };
    }
    
    // Check blocklist
    const isBlocked = this.blocklist.includes(host) || 
                     this.suspiciousPorts.includes(port);
    
    const result = {
      blocked: isBlocked,
      host: host,
      port: port
    };
    
    this.logger.log({
      timestamp: new Date().toISOString(),
      type: 'network',
      host: host,
      port: port,
      result: result,
      stack: new Error().stack,
      pid: process.pid
    });
    
    if (isBlocked) {
      this.stats.blocked++;
      console.warn(`[NET-BLOCKED] ${host}:${port}`);
    } else {
      this.stats.allowed++;
    }
    
    return result;
  }

  checkPayload(data, host) {
    if (data === undefined || data === null) return [];
    const text = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
    const findings = [];

    for (const { name, pattern, group, trustedHosts } of this.secretPatterns) {
      if (trustedHosts && this.isTrustedHost(host, trustedHosts)) continue;

      for (const match of text.matchAll(pattern)) {
        const secret = group ? match[group] : match[0];
        findings.push({ type: name, masked: this.maskSecret(secret) });
      }
    }

    return findings;
  }

  isTrustedHost(host, trustedHosts) {
    if (!host) return false;
    const h = host.toLowerCase();
    return trustedHosts.some(trusted => h === trusted || h.endsWith(`.${trusted}`));
  }

  maskSecret(value) {
    if (value.length <= 8) return '****';
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }

  checkHostname(hostname) {
    const suspiciousPatterns = [
      /\.onion$/,
      /\.tor$/,
      /\.top$/,
      /\.xyz$/,
      /\.ru$/,
      /\.cn$/
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(hostname));
  }

  getStats() {
    return this.stats;
  }

  addBlocklist(host) {
    if (!this.blocklist.includes(host)) {
      this.blocklist.push(host);
    }
  }
}

module.exports = { NetworkMonitor };
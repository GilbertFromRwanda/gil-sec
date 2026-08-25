const childProcess = require('child_process');
const { RulesEngine } = require('./rules-engine');
const { Logger } = require('./logger');

class CommandMonitor {
  constructor(options = {}) {
    this.rulesEngine = new RulesEngine();
    this.logger = new Logger(options.logFile || './security.log');
    this.options = {
      block: options.block !== false,
      alert: options.alert !== false,
      logAll: options.logAll || false,
      ...options
    };
    
    this.hookMethods();
    this.stats = {
      intercepted: 0,
      blocked: 0,
      allowed: 0
    };
  }

  hookMethods() {
    // Store original methods
    this.originalExec = childProcess.exec;
    this.originalSpawn = childProcess.spawn;
    this.originalExecFile = childProcess.execFile;
    this.originalFork = childProcess.fork;

    // Hook exec
    childProcess.exec = (command, options, callback) => {
      const result = this.analyzeCommand(command, [], 'exec');
      
      if (result.blocked) {
        const error = new Error(`[SECURITY] Command blocked: ${command}`);
        error.code = 'SECURITY_BLOCK';
        error.details = result;
        
        if (typeof callback === 'function') {
          return callback(error, null, null);
        }
        throw error;
      }

      // Execute with original
      return this.originalExec.call(this, command, options, callback);
    };

    // Hook spawn
    childProcess.spawn = (command, args, options) => {
      const result = this.analyzeCommand(command, args, 'spawn');
      
      if (result.blocked) {
        const error = new Error(`[SECURITY] Command blocked: ${command} ${args.join(' ')}`);
        error.code = 'SECURITY_BLOCK';
        error.details = result;
        throw error;
      }

      return this.originalSpawn.call(this, command, args, options);
    };

    // Hook execFile
    childProcess.execFile = (command, args, options, callback) => {
      // execFile(file[, args][, options][, callback]) — args/options are both
      // optional, so `args` may actually hold options (or even the callback),
      // as happens when Node's own exec() delegates to execFile internally.
      const argsList = Array.isArray(args) ? args : [];

      const result = this.analyzeCommand(command, argsList, 'execFile');

      if (result.blocked) {
        const error = new Error(`[SECURITY] Command blocked: ${command} ${argsList.join(' ')}`);
        error.code = 'SECURITY_BLOCK';
        error.details = result;

        const cb = [callback, options, args].find(a => typeof a === 'function');
        if (cb) {
          return cb(error, null, null);
        }
        throw error;
      }

      return this.originalExecFile.call(this, command, args, options, callback);
    };

    console.log('[Monitor] Command monitoring active');
  }

  analyzeCommand(command, args, method) {
    this.stats.intercepted++;
    
    const result = this.rulesEngine.check(command, args);
    
    // Log the attempt
    this.logger.log({
      timestamp: new Date().toISOString(),
      type: method,
      command: command,
      args: args,
      result: result,
      stack: new Error().stack,
      pid: process.pid
    });

    if (result.blocked) {
      this.stats.blocked++;
      
      // Send alert if configured
      if (this.options.alert) {
        this.sendAlert({
          ...result,
          command: command,
          args: args,
          method: method,
          timestamp: new Date().toISOString()
        });
      }
      
      console.warn(`[BLOCKED] ${command} ${args.join(' ')} - ${result.rule?.name || 'Unknown rule'}`);
    } else {
      this.stats.allowed++;
      
      if (this.options.logAll) {
        console.log(`[ALLOWED] ${command} ${args.join(' ')}`);
      }
    }

    return result;
  }

  async sendAlert(data) {
    // Send to webhook
    if (process.env.SLACK_WEBHOOK) {
      try {
        const axios = require('axios');
        await axios.post(process.env.SLACK_WEBHOOK, {
          text: `🚨 **Security Alert**\nCommand: \`${data.command}\`\nRule: ${data.rule?.name}\nSeverity: ${data.severity}\nTime: ${data.timestamp}`
        });
      } catch (err) {
        console.error('Failed to send Slack alert:', err.message);
      }
    }

    // Send to console with colors
    console.log('\x1b[31m%s\x1b[0m', `🚨 SECURITY ALERT: ${data.rule?.name}`);
    console.log('\x1b[33m%s\x1b[0m', `Command: ${data.command}`);
    console.log('\x1b[33m%s\x1b[0m', `Severity: ${data.severity}`);
  }

  getStats() {
    return {
      ...this.stats,
      rulesStats: this.rulesEngine.getStats()
    };
  }

  restore() {
    childProcess.exec = this.originalExec;
    childProcess.spawn = this.originalSpawn;
    childProcess.execFile = this.originalExecFile;
    childProcess.fork = this.originalFork;
    console.log('[Monitor] Restored original methods');
  }
}

module.exports = { CommandMonitor };
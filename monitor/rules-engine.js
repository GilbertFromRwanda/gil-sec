const fs = require('fs');
const path = require('path');

class RulesEngine {
  constructor() {
    this.rules = this.loadRules();
    this.cache = new Map();
    this.stats = {
      checked: 0,
      blocked: 0,
      allowed: 0
    };
  }

  loadRules() {
    try {
      const rulesPath = path.join(__dirname, '../config/rules.json');
      const data = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      return this.compileRules(data);
    } catch {
      return this.getDefaultRules();
    }
  }

  // config/rules.json stores patterns as strings (JSON has no regex literal),
  // so they must be compiled back into RegExp before check() can use .test() on them.
  compileRules(data) {
    return {
      ...data,
      rules: data.rules.map(rule => ({
        ...rule,
        patterns: rule.patterns.map(p => (p instanceof RegExp ? p : new RegExp(p, 'i')))
      })),
      whitelist: data.whitelist.map(p => (p instanceof RegExp ? p : new RegExp(p, 'i')))
    };
  }

  getDefaultRules() {
    return {
      version: '2.0',
      rules: [
        {
          id: 'R001',
          name: 'File Deletion',
          severity: 'critical',
          patterns: [
            /rm\s+(-rf?|--recursive|--force)/i,
            /rmdir\s+\/s/i,
            /del\s+\/f/i,
            /unlink\s+/i
          ],
          action: 'block',
          description: 'Prevents recursive/force file deletion'
        },
        {
          id: 'R002',
          name: 'System Modification',
          severity: 'critical',
          patterns: [
            /chmod\s+777/i,
            /chown\s+-R/i,
            /mount\s+/i,
            /umount\s+/i,
            /fdisk/i,
            /mkfs/i
          ],
          action: 'block',
          description: 'Blocks dangerous system modifications'
        },
        {
          id: 'R003',
          name: 'Network Attacks',
          severity: 'high',
          patterns: [
            /curl\s+.*\|.*sh/i,
            /wget\s+.*\|.*sh/i,
            /nc\s+-e/i,
            /telnet\s+/i,
            /ssh\s+-R/i
          ],
          action: 'block',
          description: 'Prevents common network attack vectors'
        },
        {
          id: 'R004',
          name: 'Process Manipulation',
          severity: 'high',
          patterns: [
            /kill\s+-9/i,
            /pkill/i,
            /killall/i,
            /systemctl\s+(stop|disable)/i
          ],
          action: 'warn',
          description: 'Alerts on process termination attempts'
        },
        {
          id: 'R005',
          name: 'Data Exfiltration',
          severity: 'critical',
          patterns: [
            /cat\s+\/etc\/passwd/i,
            /cat\s+\/etc\/shadow/i,
            /cat\s+.*\.(env|pem|key|pk)/i,
            /base64\s+.*\||curl.*-d/i
          ],
          action: 'block',
          description: 'Prevents reading sensitive files'
        },
        {
          id: 'R006',
          name: 'Command Injection',
          severity: 'critical',
          patterns: [
            /;.*rm\s/i,
            /\|\|.*rm\s/i,
            /&&.*rm\s/i,
            /`.*rm\s/i,
            /\$\(.*rm\s/i,
            /;.*wget/i,
            /;.*curl/i
          ],
          action: 'block',
          description: 'Detects command injection attempts'
        }
      ],
      whitelist: [
        /^echo\s+/i,
        /^ls\s+/i,
        /^pwd$/i,
        /^whoami$/i,
        /^date$/i
      ]
    };
  }

  check(command, args = []) {
    this.stats.checked++;
    const fullCommand = `${command} ${args.join(' ')}`.trim();

    // Check cache
    const cacheKey = fullCommand;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    // Check whitelist first
    for (const pattern of this.rules.whitelist) {
      if (pattern.test(fullCommand)) {
        const result = { blocked: false, matched: false, allowed: true };
        this.cache.set(cacheKey, result);
        return result;
      }
    }

    // Check all rules
    for (const rule of this.rules.rules) {
      for (const pattern of rule.patterns) {
        if (pattern.test(fullCommand)) {
          const result = {
            blocked: rule.action === 'block',
            matched: true,
            rule: rule,
            command: fullCommand,
            severity: rule.severity
          };
          
          if (rule.action === 'block') {
            this.stats.blocked++;
          } else {
            this.stats.allowed++;
          }
          
          this.cache.set(cacheKey, result);
          return result;
        }
      }
    }

    // No rules matched
    const result = { blocked: false, matched: false, allowed: true };
    this.stats.allowed++;
    this.cache.set(cacheKey, result);
    return result;
  }

  getStats() {
    return {
      ...this.stats,
      cacheSize: this.cache.size,
      cacheHitRate: this.stats.checked > 0 
        ? Math.round((this.cache.size / this.stats.checked) * 100) 
        : 0
    };
  }

  addRule(rule) {
    this.rules.rules.push(rule);
    this.cache.clear(); // Clear cache to apply new rule

    // RegExp objects serialize to "{}" via JSON.stringify, so patterns must be
    // written back out as their .source strings to stay loadable by loadRules().
    const serializable = {
      ...this.rules,
      rules: this.rules.rules.map(r => ({
        ...r,
        patterns: r.patterns.map(p => (p instanceof RegExp ? p.source : p))
      })),
      whitelist: this.rules.whitelist.map(p => (p instanceof RegExp ? p.source : p))
    };

    fs.writeFileSync(
      path.join(__dirname, '../config/rules.json'),
      JSON.stringify(serializable, null, 2)
    );
  }
}

module.exports = { RulesEngine };
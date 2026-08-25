const fs = require('fs');
const path = require('path');

class Logger {
  constructor(logFile = './security.log') {
    this.logFile = logFile;
    this.ensureLogFile();
    this.buffer = [];
    this.flushInterval = 1000; // Flush every second
    this.maxBufferSize = 100;
    
    // Start background flush
    this.flushTimer = setInterval(() => this.flush(), this.flushInterval);
  }

  stopFlushTimer() {
    clearInterval(this.flushTimer);
  }

  ensureLogFile() {
    const dir = path.dirname(this.logFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  log(entry) {
    this.buffer.push(entry);
    
    // Flush if buffer is full
    if (this.buffer.length >= this.maxBufferSize) {
      this.flush();
    }
  }

  flush() {
    if (this.buffer.length === 0) return;
    
    const entries = this.buffer.splice(0);
    const logLines = entries.map(entry => JSON.stringify(entry)).join('\n') + '\n';
    
    try {
      fs.appendFileSync(this.logFile, logLines);
    } catch (err) {
      console.error('Failed to write log:', err.message);
      // Re-add entries to buffer if write fails
      this.buffer.unshift(...entries);
    }
  }

  search(query, options = {}) {
    const { startTime, endTime, limit = 100 } = options;
    
    try {
      const content = fs.readFileSync(this.logFile, 'utf8');
      const lines = content.split('\n').filter(line => line.trim());
      
      let results = lines
        .map(line => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        })
        .filter(entry => entry !== null);
      
      // Apply filters
      if (startTime) {
        results = results.filter(e => e.timestamp >= startTime);
      }
      if (endTime) {
        results = results.filter(e => e.timestamp <= endTime);
      }
      if (query) {
        const searchStr = query.toLowerCase();
        results = results.filter(e => 
          JSON.stringify(e).toLowerCase().includes(searchStr)
        );
      }
      
      return results.slice(-limit);
    } catch (err) {
      console.error('Search error:', err.message);
      return [];
    }
  }

  getStats() {
    try {
      const stat = fs.statSync(this.logFile);
      const content = fs.readFileSync(this.logFile, 'utf8');
      const lines = content.split('\n').filter(line => line.trim());
      
      const blocks = lines.filter(line => {
        try {
          const entry = JSON.parse(line);
          return entry.result?.blocked === true;
        } catch {
          return false;
        }
      });
      
      return {
        fileSize: stat.size,
        totalEntries: lines.length,
        blockedEntries: blocks.length,
        lastModified: stat.mtime
      };
    } catch {
      return { fileSize: 0, totalEntries: 0, blockedEntries: 0 };
    }
  }
}

module.exports = { Logger };
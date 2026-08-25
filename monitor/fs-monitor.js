const fs = require('fs');
const path = require('path');
const { Logger } = require('./logger');

class FSMonitor {
  constructor(options = {}) {
    this.logger = new Logger(options.logFile || './security.log');
    this.protectedPaths = options.protectedPaths || [
      '/etc',
      '/bin',
      '/usr/bin',
      '/usr/local/bin',
      '/boot',
      process.env.HOME || '/home',
      '/var/log'
    ];
    
    this.allowedExtensions = options.allowedExtensions || [
      '.txt', '.log', '.tmp', '.cache'
    ];
    
    this.hookMethods();
    this.stats = {
      intercepted: 0,
      blocked: 0,
      allowed: 0
    };
  }

  hookMethods() {
    // Hook fs.unlink (delete file)
    const originalUnlink = fs.unlink;
    fs.unlink = (filePath, callback) => {
      const result = this.checkPath(filePath, 'unlink');
      
      if (result.blocked) {
        const error = new Error(`[SECURITY] Cannot delete: ${filePath}`);
        error.code = 'SECURITY_BLOCK';
        
        if (typeof callback === 'function') {
          return callback(error);
        }
        throw error;
      }
      
      return originalUnlink.call(this, filePath, callback);
    };

    // Hook fs.rmdir (delete directory)
    const originalRmdir = fs.rmdir;
    fs.rmdir = (dirPath, callback) => {
      const result = this.checkPath(dirPath, 'rmdir');
      
      if (result.blocked) {
        const error = new Error(`[SECURITY] Cannot delete directory: ${dirPath}`);
        error.code = 'SECURITY_BLOCK';
        
        if (typeof callback === 'function') {
          return callback(error);
        }
        throw error;
      }
      
      return originalRmdir.call(this, dirPath, callback);
    };

    // Hook fs.writeFile (prevent overwriting critical files)
    const originalWriteFile = fs.writeFile;
    fs.writeFile = (filePath, data, options, callback) => {
      const result = this.checkPath(filePath, 'writeFile');
      
      if (result.blocked) {
        const error = new Error(`[SECURITY] Cannot write to: ${filePath}`);
        error.code = 'SECURITY_BLOCK';
        
        if (typeof callback === 'function') {
          return callback(error);
        }
        throw error;
      }
      
      return originalWriteFile.call(this, filePath, data, options, callback);
    };

    console.log('[Monitor] File system monitoring active');
  }

  checkPath(filePath, operation) {
    this.stats.intercepted++;
    const resolvedPath = path.resolve(filePath);
    
    // Check if path is protected
    const isProtected = this.protectedPaths.some(protectedPath => {
      return resolvedPath.startsWith(path.resolve(protectedPath));
    });

    // Check if file extension is allowed
    const ext = path.extname(resolvedPath).toLowerCase();
    const isAllowed = this.allowedExtensions.includes(ext);

    const result = {
      blocked: isProtected && !isAllowed,
      path: resolvedPath,
      operation: operation,
      isProtected: isProtected,
      isAllowed: isAllowed
    };

    this.logger.log({
      timestamp: new Date().toISOString(),
      type: 'fs',
      operation: operation,
      path: resolvedPath,
      result: result,
      stack: new Error().stack,
      pid: process.pid
    });

    if (result.blocked) {
      this.stats.blocked++;
      console.warn(`[FS-BLOCKED] ${operation} ${resolvedPath}`);
    } else {
      this.stats.allowed++;
    }

    return result;
  }

  getStats() {
    return this.stats;
  }

  addProtectedPath(pathToAdd) {
    this.protectedPaths.push(pathToAdd);
  }

  removeProtectedPath(pathToRemove) {
    this.protectedPaths = this.protectedPaths.filter(p => p !== pathToRemove);
  }
}

module.exports = { FSMonitor };
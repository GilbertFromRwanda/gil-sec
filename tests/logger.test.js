const fs = require('fs');
const path = require('path');
const os = require('os');
const { Logger } = require('../monitor/logger');

describe('Logger', () => {
  let logFile;
  let logger;

  beforeEach(() => {
    jest.useFakeTimers();
    logFile = path.join(os.tmpdir(), `gil-sec-test-${Date.now()}-${Math.random()}.log`);
    logger = new Logger(logFile);
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  });

  test('creates the log file directory if missing', () => {
    const nestedFile = path.join(os.tmpdir(), 'gil-sec-nested', `test-${Date.now()}.log`);
    const nestedLogger = new Logger(nestedFile);
    expect(fs.existsSync(path.dirname(nestedFile))).toBe(true);
    fs.rmSync(path.dirname(nestedFile), { recursive: true, force: true });
  });

  test('buffers entries until flush is called', () => {
    logger.log({ timestamp: new Date().toISOString(), type: 'exec' });
    expect(fs.existsSync(logFile)).toBe(false);
    logger.flush();
    const content = fs.readFileSync(logFile, 'utf8');
    expect(content.trim().length).toBeGreaterThan(0);
  });

  test('auto-flushes once buffer reaches maxBufferSize', () => {
    for (let i = 0; i < logger.maxBufferSize; i++) {
      logger.log({ timestamp: new Date().toISOString(), type: 'exec', i });
    }
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
    expect(lines.length).toBe(logger.maxBufferSize);
    expect(logger.buffer.length).toBe(0);
  });

  test('search filters entries by query string', () => {
    logger.log({ timestamp: new Date().toISOString(), type: 'exec', command: 'rm -rf /' });
    logger.log({ timestamp: new Date().toISOString(), type: 'exec', command: 'echo hi' });
    logger.flush();

    const results = logger.search('rm -rf');
    expect(results).toHaveLength(1);
    expect(results[0].command).toBe('rm -rf /');
  });

  test('search respects the limit option', () => {
    for (let i = 0; i < 5; i++) {
      logger.log({ timestamp: new Date().toISOString(), type: 'exec', i });
    }
    logger.flush();

    const results = logger.search(null, { limit: 2 });
    expect(results).toHaveLength(2);
  });

  test('getStats reports total and blocked entry counts', () => {
    logger.log({ timestamp: new Date().toISOString(), result: { blocked: true } });
    logger.log({ timestamp: new Date().toISOString(), result: { blocked: false } });
    logger.flush();

    const stats = logger.getStats();
    expect(stats.totalEntries).toBe(2);
    expect(stats.blockedEntries).toBe(1);
  });

  test('getStats returns zeroed stats when log file does not exist', () => {
    const missingLogger = new Logger(path.join(os.tmpdir(), 'gil-sec-missing-file.log'));
    const stats = missingLogger.getStats();
    expect(stats).toEqual({ fileSize: 0, totalEntries: 0, blockedEntries: 0 });
  });
});

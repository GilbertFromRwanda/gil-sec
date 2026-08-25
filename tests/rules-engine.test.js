const { RulesEngine } = require('../monitor/rules-engine');

describe('RulesEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new RulesEngine();
  });

  test('blocks recursive/force file deletion commands', () => {
    const result = engine.check('rm', ['-rf', '/tmp/test']);
    expect(result.blocked).toBe(true);
    expect(result.rule.id).toBe('R001');
  });

  test('blocks dangerous system modification commands', () => {
    const result = engine.check('chmod', ['777', '/etc/passwd']);
    expect(result.blocked).toBe(true);
    expect(result.rule.id).toBe('R002');
  });

  test('allows whitelisted commands', () => {
    const result = engine.check('echo', ['hello']);
    expect(result.blocked).toBe(false);
    expect(result.allowed).toBe(true);
  });

  test('blocks commands that reference known Ethereum RPC endpoints', () => {
    const result = engine.check('curl', ['https://eth-mainnet.publicnode.com/']);
    expect(result.blocked).toBe(true);
    expect(result.rule.id).toBe('R007');
  });

  test('allows commands that match no rule', () => {
    const result = engine.check('git', ['status']);
    expect(result.blocked).toBe(false);
    expect(result.matched).toBe(false);
  });

  test('caches results for identical commands', () => {
    const first = engine.check('rm', ['-rf', '/tmp/test']);
    const second = engine.check('rm', ['-rf', '/tmp/test']);
    expect(second).toBe(first);
    expect(engine.getStats().cacheSize).toBe(1);
  });

  test('getStats tracks checked/blocked counts', () => {
    engine.check('rm', ['-rf', '/tmp/a']);
    engine.check('echo', ['ok']);
    const stats = engine.getStats();
    expect(stats.checked).toBe(2);
    expect(stats.blocked).toBe(1);
  });

  test('addRule persists patterns as regex source strings', () => {
    const writeSpy = jest.spyOn(require('fs'), 'writeFileSync').mockImplementation(() => {});

    engine.addRule({
      id: 'R999',
      name: 'Custom Rule',
      severity: 'high',
      patterns: [/dangerous-thing/i],
      action: 'block'
    });

    const written = JSON.parse(writeSpy.mock.calls[0][1]);
    const customRule = written.rules.find(r => r.id === 'R999');
    expect(typeof customRule.patterns[0]).toBe('string');
    expect(customRule.patterns[0]).toBe('dangerous-thing');

    writeSpy.mockRestore();
  });

  test('newly added rule is enforced immediately', () => {
    jest.spyOn(require('fs'), 'writeFileSync').mockImplementation(() => {});

    engine.addRule({
      id: 'R999',
      name: 'Custom Rule',
      severity: 'high',
      patterns: [/dangerous-thing/i],
      action: 'block'
    });

    const result = engine.check('run', ['dangerous-thing']);
    expect(result.blocked).toBe(true);
    expect(result.rule.id).toBe('R999');

    jest.restoreAllMocks();
  });
});

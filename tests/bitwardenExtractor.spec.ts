import { afterEach, describe, expect, it, vi } from 'vitest';

const execSyncMock = vi.hoisted(() => vi.fn());
vi.mock('child_process', () => ({ execSync: execSyncMock }));

import { BitwardenExtractor } from '../src/bitwardenExtractor';

const originalSession = process.env['BW_SESSION'];
const originalWarnings = process.env['NODE_NO_WARNINGS'];

afterEach(() => {
  if (originalSession === undefined) delete process.env['BW_SESSION'];
  else process.env['BW_SESSION'] = originalSession;
  if (originalWarnings === undefined) delete process.env['NODE_NO_WARNINGS'];
  else process.env['NODE_NO_WARNINGS'] = originalWarnings;
  vi.restoreAllMocks();
  execSyncMock.mockReset();
});

describe('BitwardenExtractor passkey data freshness', () => {
  it('syncs after unlocking and before reading items without logging the session token', async () => {
    const statuses = ['unauthenticated', 'unauthenticated', 'locked'];
    execSyncMock.mockImplementation((command: string) => {
      if (command.startsWith('bw status')) {
        return Buffer.from(JSON.stringify({ status: statuses.shift() }));
      }
      if (command.startsWith('bw unlock ')) return Buffer.from('session-secret\n');
      return Buffer.from('[]');
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const extractor = new BitwardenExtractor('https://vault.example.com', '/tmp/attachments', 0);

    await extractor.getBitwardenData();

    const commands = execSyncMock.mock.calls.map(([command]) => (command as string).trim());
    expect(commands.indexOf('bw sync')).toBeGreaterThan(
      commands.indexOf('bw unlock --passwordenv BW_PASSWORD --raw'),
    );
    expect(commands.indexOf('bw sync')).toBeLessThan(commands.indexOf('bw list items'));
    expect(logSpy.mock.calls.flat().join(' ')).not.toContain('session-secret');
    expect(process.env['BW_SESSION']).toContain('session-secret');
  });
});

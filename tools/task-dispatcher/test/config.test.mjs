import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { loadConfig, MAX_TIMEOUT_MS } from '../src/config.mjs';

test('loadConfig defaults autoStart.enabled to false, clamps huge timeouts, and parses repo policies', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-cfg-'));
  try {
    const cfgPath = path.join(tmpDir, 'dispatcher.config.json');
    await fs.writeFile(
      cfgPath,
      JSON.stringify({
        palace: { baseUrl: 'http://127.0.0.1:8775', tokenIdentity: 'Home-PC' },
        limits: { defaultTimeoutMs: 3_000_000_000 },
        policy: { allowedModes: ['read_only'], allowCommit: false },
        repos: {
          simple: './subrepo',
          scoped: {
            path: './scoped-repo',
            allowedModes: ['read_only', 'worktree_branch'],
            allowCommit: true,
            branchPrefix: 'agent',
          },
        },
        harnesses: {
          codex: { enabled: true, actorAliases: ['Home-PC:Codex'] },
        },
      }),
      'utf8',
    );

    const cfg = await loadConfig(cfgPath);
    assert.equal(cfg.palace.autoStart.enabled, false);
    assert.equal(cfg.palace.tokenIdentity, 'home-pc');
    assert.equal(cfg.limits.defaultTimeoutMs, MAX_TIMEOUT_MS);
    assert.equal(cfg.limits.maxTimeoutMs, MAX_TIMEOUT_MS);
    assert.deepEqual(cfg.repos.simple.allowedModes, ['read_only']);
    assert.equal(cfg.repos.simple.allowCommit, false);
    assert.deepEqual(cfg.repos.scoped.allowedModes, ['read_only', 'worktree_branch']);
    assert.equal(cfg.repos.scoped.allowCommit, true);
    assert.equal(cfg.repos.scoped.branchPrefix, 'agent/');
    assert.deepEqual(cfg.harnesses.codex.actorAliases, ['home-pc:codex']);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('loadConfig rejects non-numeric strings instead of producing NaN', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-cfg-bad-'));
  try {
    const cfgPath = path.join(tmpDir, 'bad.json');
    await fs.writeFile(
      cfgPath,
      JSON.stringify({
        palace: { baseUrl: 'http://127.0.0.1:8775' },
        limits: { maxConcurrent: 'two' },
      }),
      'utf8',
    );
    await assert.rejects(() => loadConfig(cfgPath), /limits\.maxConcurrent must be a finite number/);

    await fs.writeFile(
      cfgPath,
      JSON.stringify({
        palace: { baseUrl: 'http://127.0.0.1:8775' },
        polling: { intervalMs: 'fast' },
      }),
      'utf8',
    );
    await assert.rejects(() => loadConfig(cfgPath), /polling\.intervalMs must be a finite number/);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

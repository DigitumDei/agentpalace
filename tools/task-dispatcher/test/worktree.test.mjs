import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ensureWorktree, removeWorktree } from '../src/worktree.mjs';

const execFileAsync = promisify(execFile);

async function git(cwd, args) {
  return execFileAsync('git', args, { cwd, windowsHide: true });
}

test('ensureWorktree isolates branches, rejects main/unmanaged branches/bad baseRef, and creates worktrees safely', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-wt-'));
  const repoPath = path.join(tmpDir, 'repo');
  const wtRoot = path.join(tmpDir, 'worktrees');

  try {
    await fs.mkdir(repoPath, { recursive: true });
    await git(repoPath, ['init', '-b', 'main']);
    await git(repoPath, ['config', 'user.name', 'Test User']);
    await git(repoPath, ['config', 'user.email', 'test@example.com']);
    await fs.writeFile(path.join(repoPath, 'README.md'), 'hello\n', 'utf8');
    await git(repoPath, ['add', 'README.md']);
    await git(repoPath, ['commit', '-m', 'init']);
    await git(repoPath, ['branch', 'agent/preexisting']);

    // Missing repoPath rejected.
    await assert.rejects(
      () => ensureWorktree({ repoPath: undefined, worktreeRoot: wtRoot, taskId: 'task_1' }),
      /requires a mapped repoPath/,
    );

    // Branch without required prefix rejected (cannot check out main).
    await assert.rejects(
      () => ensureWorktree({ repoPath, worktreeRoot: wtRoot, taskId: 'task_1', branch: 'main' }),
      /must start with required prefix/,
    );

    // Pre-existing unmanaged branch rejected unless allowReuseExistingBranch=true.
    await assert.rejects(
      () => ensureWorktree({ repoPath, worktreeRoot: wtRoot, taskId: 'task_1', branch: 'agent/preexisting' }),
      /unmanaged branch/,
    );

    // Flag-like baseRef rejected.
    await assert.rejects(
      () => ensureWorktree({ repoPath, worktreeRoot: wtRoot, taskId: 'task_1', baseRef: '--force' }),
      /Invalid git baseRef/,
    );

    // Valid creation & reuse.
    const created = await ensureWorktree({ repoPath, worktreeRoot: wtRoot, taskId: 'task_demo' });
    assert.equal(created.reused, false);
    assert.equal(created.branchName, 'agent/task_demo');
    const stat = await fs.stat(path.join(created.worktreePath, 'README.md'));
    assert.equal(stat.isFile(), true);

    const reused = await ensureWorktree({ repoPath, worktreeRoot: wtRoot, taskId: 'task_demo' });
    assert.equal(reused.reused, true);

    await removeWorktree({ repoPath, worktreePath: created.worktreePath, force: true });
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

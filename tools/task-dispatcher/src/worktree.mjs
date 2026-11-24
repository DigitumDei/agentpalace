import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Sanitize a task ID into a safe directory & git branch slug across Windows and Linux.
 */
export function sanitizeSlug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || 'task';
}

async function runGit(repoPath, args) {
  const { stdout, stderr } = await execFileAsync('git', args, {
    cwd: repoPath,
    windowsHide: true,
  });
  return { stdout: stdout.trim(), stderr: stderr.trim() };
}

/**
 * Ensure an isolated git worktree exists for `(repoPath, taskId)`.
 * Reuses an existing worktree directory if already present; otherwise creates
 * a new worktree and branch based on `baseRef` (defaulting to current `HEAD`).
 */
export async function ensureWorktree({ repoPath, worktreeRoot, taskId, branch, baseRef = 'HEAD' }) {
  const slug = sanitizeSlug(taskId);
  const worktreePath = path.resolve(worktreeRoot, slug);
  const branchName = branch || `agent/${slug}`;

  try {
    const stat = await fs.stat(worktreePath);
    if (stat.isDirectory()) {
      return { worktreePath, branchName, reused: true };
    }
  } catch {
    // Does not exist yet; create it below.
  }

  await fs.mkdir(worktreeRoot, { recursive: true });

  // Check if the target branch already exists locally.
  let branchExists = false;
  try {
    await runGit(repoPath, ['show-ref', '--verify', '--quiet', `refs/heads/${branchName}`]);
    branchExists = true;
  } catch {
    branchExists = false;
  }

  if (branchExists) {
    await runGit(repoPath, ['worktree', 'add', worktreePath, branchName]);
  } else {
    await runGit(repoPath, ['worktree', 'add', '-b', branchName, worktreePath, baseRef]);
  }

  return { worktreePath, branchName, reused: false };
}

/**
 * Remove a worktree cleanly (optional maintenance helper).
 */
export async function removeWorktree({ repoPath, worktreePath, force = false }) {
  const args = ['worktree', 'remove'];
  if (force) args.push('--force');
  args.push(worktreePath);
  await runGit(repoPath, args);
}

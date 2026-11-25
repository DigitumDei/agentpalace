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

/**
 * Validate that a worktree branch name starts with the configured prefix
 * (e.g. `"agent/"`) and cannot target `main`/`master` or pass git flags.
 */
export function validateBranchName(branchName, branchPrefix = 'agent/') {
  if (typeof branchName !== 'string' || !branchName.trim()) {
    throw new Error('Branch name must be a non-empty string.');
  }
  const trimmed = branchName.trim();
  if (
    trimmed.startsWith('-') ||
    trimmed.startsWith('/') ||
    trimmed.endsWith('/') ||
    trimmed.includes('..') ||
    trimmed.includes('@{') ||
    trimmed.endsWith('.lock') ||
    !/^[A-Za-z0-9._/-]+$/.test(trimmed)
  ) {
    throw new Error(`Invalid git branch name "${branchName}".`);
  }
  if (branchPrefix && !trimmed.startsWith(branchPrefix)) {
    throw new Error(`Branch "${trimmed}" must start with required prefix "${branchPrefix}".`);
  }
  return trimmed;
}

/**
 * Validate a git start-point ref so option-like strings (`--force`) are rejected.
 */
export function validateBaseRef(baseRef) {
  if (typeof baseRef !== 'string' || !baseRef.trim()) {
    throw new Error('baseRef must be a non-empty string.');
  }
  const trimmed = baseRef.trim();
  if (
    trimmed.startsWith('-') ||
    trimmed.startsWith('/') ||
    trimmed.endsWith('/') ||
    trimmed.includes('..') ||
    trimmed.includes('@{') ||
    trimmed.endsWith('.lock') ||
    !/^[A-Za-z0-9._/-]+$/.test(trimmed)
  ) {
    throw new Error(`Invalid git baseRef "${baseRef}".`);
  }
  return trimmed;
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
 * Refuses to check out pre-existing unmanaged branches unless
 * `allowReuseExistingBranch` is explicitly set (i.e. tracked in dispatcher state).
 */
export async function ensureWorktree({
  repoPath,
  worktreeRoot,
  taskId,
  branch,
  baseRef = 'HEAD',
  branchPrefix = 'agent/',
  allowReuseExistingBranch = false,
}) {
  if (!repoPath || typeof repoPath !== 'string') {
    throw new Error('ensureWorktree requires a mapped repoPath.');
  }

  const slug = sanitizeSlug(taskId);
  const worktreePath = path.resolve(worktreeRoot, slug);
  const branchName = validateBranchName(branch || `${branchPrefix}${slug}`, branchPrefix);
  const safeBaseRef = validateBaseRef(baseRef);

  try {
    const stat = await fs.stat(worktreePath);
    if (stat.isDirectory()) {
      try {
        await fs.access(path.join(worktreePath, '.git'));
      } catch {
        throw new Error(`Directory "${worktreePath}" already exists but is not a git worktree.`);
      }
      return { worktreePath, branchName, reused: true };
    }
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  await fs.mkdir(worktreeRoot, { recursive: true });

  // Resolve baseRef unambiguously to a commit SHA before worktree creation.
  const { stdout: resolvedCommit } = await runGit(repoPath, [
    'rev-parse',
    '--verify',
    '--end-of-options',
    `${safeBaseRef}^{commit}`,
  ]);

  let branchExists = false;
  try {
    await runGit(repoPath, ['show-ref', '--verify', '--quiet', `refs/heads/${branchName}`]);
    branchExists = true;
  } catch {
    branchExists = false;
  }

  if (branchExists) {
    if (!allowReuseExistingBranch) {
      throw new Error(
        `Refusing to check out pre-existing unmanaged branch "${branchName}". Only dispatcher-created branches may be reused.`,
      );
    }
    await runGit(repoPath, ['worktree', 'add', '--', worktreePath, branchName]);
  } else {
    await runGit(repoPath, ['worktree', 'add', '-b', branchName, worktreePath, resolvedCommit]);
  }

  return { worktreePath, branchName, reused: false };
}

/**
 * Remove a worktree cleanly (optional maintenance helper).
 */
export async function removeWorktree({ repoPath, worktreePath, force = false }) {
  if (!repoPath || typeof repoPath !== 'string') {
    throw new Error('removeWorktree requires a mapped repoPath.');
  }
  const args = ['worktree', 'remove'];
  if (force) args.push('--force');
  args.push('--', worktreePath);
  await runGit(repoPath, args);
}

/**
 * Build the command, arguments, and prompt-delivery mode for each supported harness.
 * Verified against local CLI `--help` output on Windows and Linux:
 * - `claude`: `claude -p` reads prompt cleanly from stdin
 * - `codex`: `codex exec -` explicitly reads instructions from stdin
 * - `opencode`: `opencode run --format json` (supports `--attach <url>`)
 * - `custom`: arbitrary command + args template (`{taskId}`, `{worktree}`, `{promptFile}`)
 */
export function buildHarnessInvocation(harness, { taskId, worktreePath, prompt }) {
  const type = (harness.type || harness.name).toLowerCase();

  if (type === 'claude') {
    return {
      command: harness.command || 'claude',
      args: ['-p', ...harness.extraArgs],
      promptDelivery: 'stdin',
      prompt,
      env: harness.env,
    };
  }

  if (type === 'codex') {
    return {
      command: harness.command || 'codex',
      args: ['exec', ...harness.extraArgs, '-'],
      promptDelivery: 'stdin',
      prompt,
      env: harness.env,
    };
  }

  if (type === 'opencode') {
    const args = ['run', '--format', 'json'];
    if (harness.attachUrl) {
      args.push('--attach', harness.attachUrl);
    }
    if (worktreePath) {
      args.push('--dir', worktreePath);
    }
    args.push(...harness.extraArgs);
    // Pass prompt via a temp file attached with `-f` or stdin depending on config.
    if (harness.promptDelivery === 'file') {
      args.push('-f', '{promptFile}', `Execute AgentPalace task ${taskId} per the attached dispatch prompt.`);
      return {
        command: harness.command || 'opencode',
        args,
        promptDelivery: 'file',
        prompt,
        env: harness.env,
      };
    }
    return {
      command: harness.command || 'opencode',
      args,
      promptDelivery: 'stdin',
      prompt,
      env: harness.env,
    };
  }

  // Custom harness (e.g. Antigravity `agy` or `AntiGravityContainer/run-task.ps1`).
  const args = (harness.args || []).map((arg) =>
    arg
      .replaceAll('{taskId}', taskId)
      .replaceAll('{worktree}', worktreePath || ''),
  );
  args.push(...harness.extraArgs);

  return {
    command: harness.command,
    args,
    promptDelivery: harness.promptDelivery || 'stdin',
    prompt,
    env: harness.env,
  };
}

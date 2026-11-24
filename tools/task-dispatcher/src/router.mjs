const TERMINAL_STATES = new Set(['completed', 'cancelled', 'failed', 'expired']);

/**
 * Extract an optional structured dispatch contract from a task's description.
 *
 * Supported formats inside `task.description`:
 * 1. A fenced block tagged ```dispatcher ... ``` containing JSON.
 * 2. A fenced block tagged ```json ... ``` whose top-level object either has a
 *    `"dispatcher": { ... }` key or at least one recognized dispatch key
 *    (`target`, `mode`, `repo`, `executor`, `maxRounds`).
 */
export function parseDispatchContract(description = '') {
  if (!description || typeof description !== 'string') {
    return {};
  }

  const fenceRe = /```(dispatcher|json)\s*\r?\n([\s\S]*?)```/gi;
  let match;
  while ((match = fenceRe.exec(description)) !== null) {
    const tag = match[1].toLowerCase();
    const raw = match[2].trim();
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        continue;
      }
      if (tag === 'dispatcher') {
        return normalizeContract(parsed);
      }
      if (parsed.dispatcher && typeof parsed.dispatcher === 'object') {
        return normalizeContract(parsed.dispatcher);
      }
      if ('target' in parsed || 'mode' in parsed || 'repo' in parsed || 'executor' in parsed) {
        return normalizeContract(parsed);
      }
    } catch {
      // Ignore non-JSON or unrelated code blocks in task descriptions.
    }
  }

  return {};
}

function isSafeBranchName(branch) {
  if (typeof branch !== 'string') return false;
  const trimmed = branch.trim();
  if (!trimmed || trimmed.startsWith('-') || trimmed.startsWith('/') || trimmed.endsWith('/')) return false;
  if (trimmed.includes('..') || trimmed.includes('@{') || trimmed.endsWith('.lock')) return false;
  return /^[A-Za-z0-9._/-]+$/.test(trimmed);
}

function normalizeContract(obj) {
  const mode = obj.mode ?? 'read_only';
  const maxRounds =
    typeof obj.maxRounds === 'number' && Number.isFinite(obj.maxRounds)
      ? Math.max(1, Math.floor(obj.maxRounds))
      : undefined;
  const timeoutMs =
    typeof obj.timeoutMs === 'number' && Number.isFinite(obj.timeoutMs)
      ? Math.max(10000, Math.floor(obj.timeoutMs))
      : undefined;
  const branch = isSafeBranchName(obj.branch) ? obj.branch.trim() : undefined;

  return {
    target: typeof obj.target === 'string' ? obj.target.trim().toLowerCase() : undefined,
    executor: typeof obj.executor === 'string' ? obj.executor.trim() : undefined,
    mode: ['read_only', 'worktree_branch', 'draft_pr'].includes(mode) ? mode : 'read_only',
    repo: typeof obj.repo === 'string' ? obj.repo.trim().toLowerCase() : undefined,
    baseRef: typeof obj.baseRef === 'string' && obj.baseRef.trim() ? obj.baseRef.trim() : undefined,
    branch,
    maxRounds,
    timeoutMs,
    allowCommit: Boolean(obj.allowCommit),
    allowPush: Boolean(obj.allowPush),
  };
}

export function isTerminalState(state) {
  return TERMINAL_STATES.has(state);
}

/**
 * Determine which enabled harness should handle a pending task.
 * Precedence:
 * 1. Explicit `contract.target`
 * 2. `task.owner` (when retained across a scheduling wait)
 * 3. `task.executor_affinity` (if it matches an enabled harness name)
 */
export function resolveTargetHarness(task, contract, enabledHarnesses) {
  const enabledNames = Object.keys(enabledHarnesses);
  const candidates = [
    contract.target,
    typeof task.owner === 'string' ? task.owner.trim().toLowerCase() : undefined,
    typeof task.executor_affinity === 'string' ? task.executor_affinity.trim().toLowerCase() : undefined,
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (candidate === 'any') {
      return enabledNames[0] ?? null;
    }
    if (enabledHarnesses[candidate]) {
      return candidate;
    }
  }
  return null;
}

/**
 * Evaluate whether a pending task is eligible to be dispatched on this host.
 */
export function evaluatePendingTask({ task, contract, config, activeRuns, roundsUsed, depsCompleted }) {
  if (task.state !== 'pending') {
    return { eligible: false, reason: `state is ${task.state}` };
  }
  if (activeRuns.has(task.task_id)) {
    return { eligible: false, reason: 'already running locally' };
  }
  if (contract.executor && contract.executor !== config.executorId) {
    return { eligible: false, reason: `targeted to executor "${contract.executor}", this host is "${config.executorId}"` };
  }
  if (!depsCompleted) {
    return { eligible: false, reason: 'waiting on unfinished dependencies' };
  }

  const enabledHarnesses = Object.fromEntries(
    Object.entries(config.harnesses).filter(([, h]) => h.enabled),
  );
  const harnessName = resolveTargetHarness(task, contract, enabledHarnesses);
  if (!harnessName) {
    return { eligible: false, reason: 'no matching enabled harness' };
  }

  const maxRounds = contract.maxRounds ?? config.limits.defaultMaxRounds;
  if (roundsUsed >= maxRounds) {
    return { eligible: false, reason: `round cap reached (${roundsUsed}/${maxRounds})`, capReached: true };
  }

  const repoPath = contract.repo ? config.repos[contract.repo] : undefined;
  if (contract.repo && !repoPath) {
    return { eligible: false, reason: `repo "${contract.repo}" not mapped in config.repos` };
  }
  if ((contract.mode === 'worktree_branch' || contract.mode === 'draft_pr') && !repoPath) {
    return { eligible: false, reason: `mode "${contract.mode}" requires a mapped contract.repo` };
  }

  return {
    eligible: true,
    harnessName,
    repoPath,
    maxRounds,
  };
}

/**
 * Build the concise, authoritative launch prompt.
 * Follows `docs/Agent-Task-Handoffs.md`: pass IDs and policy, not a duplicate spec.
 */
export function buildBootstrapPrompt({ task, contract, harnessName, worktreePath, trigger, messageIds = [], claimMode = 'agent' }) {
  const lines = [
    `You have been dispatched by the local AgentPalace task dispatcher as agent "${harnessName}".`,
    '',
    `Trigger: ${trigger === 'inbox' ? 'unread inbox message(s)' : 'pending task assignment'}`,
    `Task ID: ${task.task_id}`,
    `Wing: ${task.wing}`,
    `Title: ${task.title}`,
  ];

  if (messageIds.length > 0) {
    lines.push(`Message ID(s) to read first: ${messageIds.join(', ')}`);
  }
  if (worktreePath) {
    lines.push(`Working directory (isolated worktree): ${worktreePath}`);
  }

  const steps = [
    `Retrieve task "${task.task_id}" via agentpalace_task_get — the task description is the authoritative specification.`,
  ];
  if (messageIds.length > 0) {
    steps.push(
      `Read the triggering message(s) (${messageIds.join(', ')}) via agentpalace_message_get and acknowledge them with agentpalace_message_acknowledge once handled.`,
    );
  }
  if (claimMode === 'agent' && trigger === 'pending') {
    steps.push(
      `Claim task "${task.task_id}" as "${harnessName}" via agentpalace_task_claim before making changes.`,
    );
  }
  steps.push('Execute only the bounded scope described in the task. Preserve any unrelated dirty files.');
  steps.push(
    claimMode === 'dispatcher'
      ? 'When finished (or if blocked/awaiting review), publish results via agentpalace_result_put / agentpalace_message_send. The dispatcher owns the task lease and will inspect/reconcile state on exit.'
      : 'When finished (or if blocked/awaiting review), publish results via agentpalace_result_put / agentpalace_message_send and transition the task state (`input_required` for review/handoff, or `completed` if final).',
  );

  lines.push('', 'Workflow protocol:');
  steps.forEach((step, idx) => {
    lines.push(`${idx + 1}. ${step}`);
  });

  lines.push('', 'Repository guardrails:');
  if (contract.mode === 'read_only') {
    lines.push('- READ-ONLY task: do not modify repository files, commit, or push.');
  } else {
    lines.push(contract.allowCommit
      ? '- Commits are permitted on the assigned worktree branch only. NEVER commit or push to main/master.'
      : '- Do NOT commit or push unless the task explicitly authorizes it. NEVER push to main/master.');
    if (contract.mode === 'draft_pr' && contract.allowPush) {
      lines.push('- Draft PR publication is authorized on the feature branch only.');
    }
  }

  return lines.join('\n') + '\n';
}

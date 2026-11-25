import { MAX_TIMEOUT_MS } from './config.mjs';

const TERMINAL_STATES = new Set(['completed', 'cancelled', 'failed', 'expired']);
const VALID_MODES = new Set(['read_only', 'worktree_branch', 'draft_pr']);

/**
 * Extract an optional structured dispatch contract from a task's description.
 * Always returns a normalized contract defaulting to `mode: "read_only"` and
 * `allowCommit: false`, `allowPush: false`.
 */
export function parseDispatchContract(description = '') {
  if (!description || typeof description !== 'string') {
    return normalizeContract({});
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

  return normalizeContract({});
}

export function isSafeBranchName(branch) {
  if (typeof branch !== 'string') return false;
  const trimmed = branch.trim();
  if (!trimmed || trimmed.startsWith('-') || trimmed.startsWith('/') || trimmed.endsWith('/')) return false;
  if (trimmed.includes('..') || trimmed.includes('@{') || trimmed.endsWith('.lock')) return false;
  return /^[A-Za-z0-9._/-]+$/.test(trimmed);
}

export function isSafeGitRef(ref) {
  if (typeof ref !== 'string') return false;
  const trimmed = ref.trim();
  if (!trimmed || trimmed.startsWith('-') || trimmed.startsWith('/') || trimmed.endsWith('/')) return false;
  if (trimmed.includes('..') || trimmed.includes('@{') || trimmed.endsWith('.lock')) return false;
  return /^[A-Za-z0-9._/-]+$/.test(trimmed);
}

function normalizeContract(obj = {}) {
  const mode = typeof obj.mode === 'string' && VALID_MODES.has(obj.mode) ? obj.mode : 'read_only';
  const maxRounds =
    typeof obj.maxRounds === 'number' && Number.isFinite(obj.maxRounds)
      ? Math.max(1, Math.floor(obj.maxRounds))
      : undefined;
  const timeoutMs =
    typeof obj.timeoutMs === 'number' && Number.isFinite(obj.timeoutMs)
      ? Math.min(MAX_TIMEOUT_MS, Math.max(10000, Math.floor(obj.timeoutMs)))
      : undefined;

  const hasBranch = obj.branch !== undefined && obj.branch !== null && obj.branch !== '';
  const branchValid = !hasBranch || isSafeBranchName(obj.branch);
  const branch = hasBranch && branchValid ? obj.branch.trim() : undefined;

  const hasBaseRef = obj.baseRef !== undefined && obj.baseRef !== null && obj.baseRef !== '';
  const baseRefValid = !hasBaseRef || isSafeGitRef(obj.baseRef);
  const baseRef = hasBaseRef && baseRefValid ? obj.baseRef.trim() : undefined;

  return {
    target: typeof obj.target === 'string' ? obj.target.trim().toLowerCase() : undefined,
    executor: typeof obj.executor === 'string' ? obj.executor.trim() : undefined,
    mode,
    repo: typeof obj.repo === 'string' ? obj.repo.trim().toLowerCase() : undefined,
    baseRef,
    baseRefInvalid: hasBaseRef && !baseRefValid,
    branch,
    branchInvalid: hasBranch && !branchValid,
    maxRounds,
    timeoutMs,
    allowCommit: Boolean(obj.allowCommit),
    allowPush: Boolean(obj.allowPush),
  };
}

export function isTerminalState(state) {
  return TERMINAL_STATES.has(state);
}

function normalizeWingName(wing) {
  if (typeof wing !== 'string') return '';
  const trimmed = wing.trim().toLowerCase();
  if (!trimmed) return '';
  return trimmed.startsWith('wing_') ? trimmed : `wing_${trimmed}`;
}

/**
 * Resolve a repo mapping entry (supporting either a legacy path string or a
 * per-repo policy object `{ path, allowedModes, allowCommit, allowPush, branchPrefix }`).
 */
export function resolveRepoPolicy(config, repoKey) {
  if (!repoKey) return null;
  const raw = config.repos?.[repoKey];
  if (!raw) return null;
  const defaults = config.policy ?? {};
  const defaultModes = defaults.allowedModes ?? ['read_only', 'worktree_branch'];
  const defaultPrefix = defaults.branchPrefix ?? 'agent/';

  if (typeof raw === 'string') {
    return {
      path: raw,
      allowedModes: [...defaultModes],
      allowCommit: Boolean(defaults.allowCommit),
      allowPush: Boolean(defaults.allowPush),
      branchPrefix: defaultPrefix,
    };
  }
  if (raw && typeof raw === 'object' && typeof raw.path === 'string' && raw.path.trim()) {
    return {
      path: raw.path,
      allowedModes: Array.isArray(raw.allowedModes) ? raw.allowedModes : [...defaultModes],
      allowCommit: raw.allowCommit !== undefined ? Boolean(raw.allowCommit) : Boolean(defaults.allowCommit),
      allowPush: raw.allowPush !== undefined ? Boolean(raw.allowPush) : Boolean(defaults.allowPush),
      branchPrefix: raw.branchPrefix ?? defaultPrefix,
    };
  }
  return null;
}

/**
 * Determine which enabled harness should handle a pending task.
 * Supports exact harness names, `actorAliases`, and server-namespaced
 * `<token-identity>:<harness>` actors produced by `resolve_coordination_actor()`.
 */
export function resolveTargetHarness(task, contract, enabledHarnesses, { tokenIdentity = '' } = {}) {
  const enabledNames = Object.keys(enabledHarnesses);
  const aliasToHarness = new Map();
  for (const [name, cfg] of Object.entries(enabledHarnesses)) {
    aliasToHarness.set(name, name);
    for (const alias of cfg.actorAliases ?? []) {
      aliasToHarness.set(String(alias).trim().toLowerCase(), name);
    }
  }

  const candidates = [
    contract?.target,
    typeof task.owner === 'string' ? task.owner.trim().toLowerCase() : undefined,
    typeof task.executor_affinity === 'string' ? task.executor_affinity.trim().toLowerCase() : undefined,
  ].filter(Boolean);

  const normalizedIdentity = String(tokenIdentity || '').trim().toLowerCase();

  for (const candidate of candidates) {
    if (candidate === 'any') {
      return enabledNames[0] ?? null;
    }
    if (aliasToHarness.has(candidate)) {
      return aliasToHarness.get(candidate);
    }
    const colonIdx = candidate.indexOf(':');
    if (colonIdx > 0 && colonIdx === candidate.lastIndexOf(':')) {
      const prefix = candidate.slice(0, colonIdx);
      const worker = candidate.slice(colonIdx + 1);
      if (enabledHarnesses[worker]) {
        const prefixAllowed =
          normalizedIdentity === '*' ||
          (normalizedIdentity ? prefix === normalizedIdentity : prefix === 'dispatcher');
        if (prefixAllowed) {
          return worker;
        }
      }
    }
  }
  return null;
}

/**
 * Shared local policy, repo-mapping, mode, git-ref, and cap validation for both
 * pending tasks and inbox-triggered wakeups. Local config is always the ceiling.
 */
export function applyPolicyAndValidate({ task, contract = {}, config, senders }) {
  const wings = Array.isArray(config.polling?.wings) ? config.polling.wings : [];
  if (wings.length > 0) {
    const taskWing = normalizeWingName(task.wing);
    const allowedWings = new Set(wings.map(normalizeWingName).filter(Boolean));
    if (!allowedWings.has(taskWing)) {
      return { ok: false, reason: `wing "${task.wing}" not in polling.wings` };
    }
  }

  const allowedCreators = config.policy?.allowedCreators ?? [];
  if (allowedCreators.length > 0) {
    const creator = String(task.created_by || '').trim().toLowerCase();
    if (!allowedCreators.includes(creator)) {
      return { ok: false, reason: `creator "${task.created_by}" not in policy.allowedCreators` };
    }
  }

  if (Array.isArray(senders) && (config.policy?.allowedSenders?.length ?? 0) > 0) {
    const allowedSenders = new Set(config.policy.allowedSenders);
    const hasAllowedSender = senders.some((s) => allowedSenders.has(String(s || '').trim().toLowerCase()));
    if (!hasAllowedSender) {
      return { ok: false, reason: 'no inbox message from policy.allowedSenders' };
    }
  }

  if (contract.executor && contract.executor !== config.executorId) {
    return {
      ok: false,
      reason: `targeted to executor "${contract.executor}", this host is "${config.executorId}"`,
    };
  }

  const effectiveMode = contract.mode ?? 'read_only';
  if (!VALID_MODES.has(effectiveMode)) {
    return { ok: false, reason: `unsupported mode "${effectiveMode}"` };
  }

  const repoPolicy = contract.repo ? resolveRepoPolicy(config, contract.repo) : null;
  if (contract.repo && !repoPolicy) {
    return { ok: false, reason: `repo "${contract.repo}" not mapped in config.repos` };
  }
  if ((effectiveMode === 'worktree_branch' || effectiveMode === 'draft_pr') && !repoPolicy) {
    return { ok: false, reason: `mode "${effectiveMode}" requires a mapped contract.repo` };
  }

  const allowedModes = repoPolicy?.allowedModes ?? config.policy?.allowedModes ?? ['read_only', 'worktree_branch'];
  if (!allowedModes.includes(effectiveMode)) {
    return { ok: false, reason: `mode "${effectiveMode}" not allowed by local policy` };
  }

  const branchPrefix = repoPolicy?.branchPrefix ?? config.policy?.branchPrefix ?? 'agent/';
  if (effectiveMode === 'worktree_branch' || effectiveMode === 'draft_pr') {
    if (contract.branchInvalid) {
      return { ok: false, reason: 'invalid branch name in dispatch contract' };
    }
    if (contract.branch && !contract.branch.startsWith(branchPrefix)) {
      return {
        ok: false,
        reason: `branch "${contract.branch}" must start with required prefix "${branchPrefix}"`,
      };
    }
    if (contract.baseRefInvalid) {
      return { ok: false, reason: 'invalid baseRef in dispatch contract' };
    }
  }

  const maxRoundsDefault = config.limits?.defaultMaxRounds ?? 5;
  const maxRoundsCeiling = config.limits?.maxRoundsCap ?? maxRoundsDefault;
  const effectiveMaxRounds = Math.min(contract.maxRounds ?? maxRoundsDefault, maxRoundsCeiling);

  const defaultTimeout = config.limits?.defaultTimeoutMs ?? 1800000;
  const maxTimeoutCeiling = Math.min(config.limits?.maxTimeoutMs ?? defaultTimeout, MAX_TIMEOUT_MS);
  const effectiveTimeoutMs = Math.min(contract.timeoutMs ?? defaultTimeout, maxTimeoutCeiling);

  const canCommit = repoPolicy ? repoPolicy.allowCommit : Boolean(config.policy?.allowCommit);
  const canPush = repoPolicy ? repoPolicy.allowPush : Boolean(config.policy?.allowPush);

  const effectiveContract = {
    ...contract,
    mode: effectiveMode,
    allowCommit: Boolean(contract.allowCommit && canCommit),
    allowPush: Boolean(contract.allowPush && canPush),
    maxRounds: effectiveMaxRounds,
    timeoutMs: effectiveTimeoutMs,
  };

  return {
    ok: true,
    repoPath: repoPolicy?.path,
    branchPrefix,
    effectiveContract,
  };
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
  if (!depsCompleted) {
    return { eligible: false, reason: 'waiting on unfinished dependencies' };
  }

  const enabledHarnesses = Object.fromEntries(
    Object.entries(config.harnesses).filter(([, h]) => h.enabled),
  );
  const harnessName = resolveTargetHarness(task, contract, enabledHarnesses, {
    tokenIdentity: config.palace?.tokenIdentity,
  });
  if (!harnessName) {
    return { eligible: false, reason: 'no matching enabled harness' };
  }

  const policyCheck = applyPolicyAndValidate({ task, contract, config });
  if (!policyCheck.ok) {
    return { eligible: false, reason: policyCheck.reason };
  }

  const maxRounds = policyCheck.effectiveContract.maxRounds;
  if (roundsUsed >= maxRounds) {
    return { eligible: false, reason: `round cap reached (${roundsUsed}/${maxRounds})`, capReached: true };
  }

  return {
    eligible: true,
    harnessName,
    repoPath: policyCheck.repoPath,
    branchPrefix: policyCheck.branchPrefix,
    maxRounds,
    effectiveContract: policyCheck.effectiveContract,
  };
}

/**
 * Evaluate whether an inbox-triggered wake for `task` is eligible on this host.
 * Enforces the same repo, mode, creator/sender, git-ref, and cap checks as pending tasks.
 */
export function evaluateInboxTask({ task, contract, config, activeRuns, roundsUsed, messages = [] }) {
  if (isTerminalState(task.state)) {
    return { eligible: false, reason: `terminal state ${task.state}` };
  }
  if (activeRuns.has(task.task_id)) {
    return { eligible: false, reason: 'already running locally' };
  }

  const allowedSenders = config.policy?.allowedSenders ?? [];
  const eligibleMessages =
    allowedSenders.length > 0
      ? messages.filter((m) => allowedSenders.includes(String(m.sender || '').trim().toLowerCase()))
      : messages;

  if (eligibleMessages.length === 0) {
    return { eligible: false, reason: 'no inbox message from policy.allowedSenders' };
  }

  const policyCheck = applyPolicyAndValidate({
    task,
    contract,
    config,
    senders: eligibleMessages.map((m) => m.sender),
  });
  if (!policyCheck.ok) {
    return { eligible: false, reason: policyCheck.reason };
  }

  const maxRounds = policyCheck.effectiveContract.maxRounds;
  if (roundsUsed >= maxRounds) {
    return { eligible: false, reason: `round cap reached (${roundsUsed}/${maxRounds})`, capReached: true };
  }

  return {
    eligible: true,
    repoPath: policyCheck.repoPath,
    branchPrefix: policyCheck.branchPrefix,
    maxRounds,
    effectiveContract: policyCheck.effectiveContract,
    messages: eligibleMessages,
  };
}

/**
 * Build the concise, authoritative launch prompt.
 * Follows `docs/Agent-Task-Handoffs.md`: pass IDs and policy, not a duplicate spec.
 */
export function buildBootstrapPrompt({ task, contract = {}, harnessName, worktreePath, trigger, messageIds = [], claimMode = 'agent' }) {
  const effectiveMode = contract?.mode ?? 'read_only';
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
      ? 'When finished (or if blocked/awaiting review), publish results via agentpalace_result_put / agentpalace_message_send. The dispatcher owns the task lease and will reconcile task state after you exit.'
      : 'When finished (or if blocked/awaiting review), publish results via agentpalace_result_put / agentpalace_message_send and transition the task state (`input_required` for review/handoff, or `completed` if final).',
  );

  lines.push('', 'Workflow protocol:');
  steps.forEach((step, idx) => {
    lines.push(`${idx + 1}. ${step}`);
  });

  lines.push('', 'Repository guardrails:');
  if (effectiveMode === 'read_only') {
    lines.push('- READ-ONLY task: do not modify repository files, commit, or push.');
  } else {
    lines.push(contract.allowCommit
      ? '- Commits are permitted on the assigned worktree branch only. NEVER commit or push to main/master.'
      : '- Do NOT commit or push unless the task explicitly authorizes it. NEVER push to main/master.');
    if (effectiveMode === 'draft_pr' && contract.allowPush) {
      lines.push('- Draft PR publication is authorized on the feature branch only.');
    }
  }

  return lines.join('\n') + '\n';
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDispatchContract,
  resolveTargetHarness,
  evaluatePendingTask,
  evaluateInboxTask,
  buildBootstrapPrompt,
} from '../src/router.mjs';
import { MAX_TIMEOUT_MS } from '../src/config.mjs';
import { buildHarnessInvocation } from '../src/harnesses.mjs';

test('parseDispatchContract parses fenced dispatcher block and defaults missing blocks to read_only', () => {
  const desc = `Review PR #42.

\`\`\`dispatcher
{
  "target": "Claude",
  "mode": "worktree_branch",
  "repo": "Example-App",
  "executor": "home-pc",
  "maxRounds": 3,
  "allowCommit": true
}
\`\`\`
`;
  const contract = parseDispatchContract(desc);
  assert.equal(contract.target, 'claude');
  assert.equal(contract.mode, 'worktree_branch');
  assert.equal(contract.repo, 'example-app');
  assert.equal(contract.executor, 'home-pc');
  assert.equal(contract.maxRounds, 3);
  assert.equal(contract.allowCommit, true);
  assert.equal(contract.allowPush, false);

  const missing = parseDispatchContract('Plain task with no dispatcher fence.');
  assert.equal(missing.mode, 'read_only');
  assert.equal(missing.allowCommit, false);
  assert.equal(missing.allowPush, false);
});

test('parseDispatchContract ignores unrelated or invalid JSON blocks and returns read_only defaults', () => {
  const desc = `Some task\n\`\`\`json\n{ not valid json\n\`\`\`\n\`\`\`json\n{"unrelated": true}\n\`\`\``;
  const contract = parseDispatchContract(desc);
  assert.equal(contract.mode, 'read_only');
  assert.equal(contract.target, undefined);
  assert.equal(contract.allowCommit, false);
});

test('resolveTargetHarness resolves exact, alias, and namespaced <tokenIdentity>:<worker> actors', () => {
  const enabled = {
    claude: { enabled: true, actorAliases: [] },
    codex: { enabled: true, actorAliases: ['custom-codex-alias'] },
  };
  assert.equal(resolveTargetHarness({ owner: 'codex' }, { target: 'claude' }, enabled), 'claude');
  assert.equal(resolveTargetHarness({ owner: 'codex' }, {}, enabled), 'codex');
  assert.equal(resolveTargetHarness({ executor_affinity: 'opencode' }, {}, enabled), null);
  assert.equal(resolveTargetHarness({}, { target: 'any' }, enabled), 'claude');

  // Namespaced HTTP actor resolution (resolve_coordination_actor format: <identity>:<worker>).
  assert.equal(
    resolveTargetHarness({ owner: 'home-pc:codex' }, {}, enabled, { tokenIdentity: 'home-pc' }),
    'codex',
  );
  // Reject namespaced actor belonging to another token identity.
  assert.equal(
    resolveTargetHarness({ owner: 'other-user:codex' }, {}, enabled, { tokenIdentity: 'home-pc' }),
    null,
  );
  // Default auto-started ephemeral token name 'dispatcher' matches even without explicit tokenIdentity.
  assert.equal(resolveTargetHarness({ owner: 'dispatcher:codex' }, {}, enabled), 'codex');
  // Explicit alias works regardless of prefix.
  assert.equal(resolveTargetHarness({ executor_affinity: 'custom-codex-alias' }, {}, enabled), 'codex');
});

test('evaluatePendingTask enforces policy ceiling, branch prefix, git refs, creator allowlist, and caps', () => {
  const config = {
    executorId: 'home-pc',
    palace: { tokenIdentity: '' },
    polling: { wings: ['wing_agentpalace'] },
    limits: { defaultMaxRounds: 3, maxRoundsCap: 4, defaultTimeoutMs: 60000, maxTimeoutMs: 120000 },
    policy: {
      allowedCreators: ['dion', 'claude'],
      allowedSenders: ['dion', 'claude'],
      allowedModes: ['read_only', 'worktree_branch'],
      allowCommit: false,
      allowPush: false,
      branchPrefix: 'agent/',
    },
    repos: {
      agentpalace: {
        path: '/repos/agentpalace',
        allowedModes: ['read_only', 'worktree_branch'],
        allowCommit: true,
        allowPush: false,
        branchPrefix: 'agent/',
      },
    },
    harnesses: {
      claude: { enabled: true, maxConcurrent: 1, actorAliases: [] },
      codex: { enabled: false, maxConcurrent: 1, actorAliases: [] },
    },
  };

  const baseTask = {
    task_id: 'task_1',
    state: 'pending',
    owner: 'claude',
    wing: 'wing_agentpalace',
    created_by: 'dion',
  };

  // Disallowed creator rejected.
  assert.equal(
    evaluatePendingTask({
      task: { ...baseTask, created_by: 'untrusted' },
      contract: parseDispatchContract(''),
      config,
      activeRuns: new Map(),
      roundsUsed: 0,
      depsCompleted: true,
    }).eligible,
    false,
  );

  // Disallowed wing rejected.
  assert.equal(
    evaluatePendingTask({
      task: { ...baseTask, wing: 'wing_other' },
      contract: parseDispatchContract(''),
      config,
      activeRuns: new Map(),
      roundsUsed: 0,
      depsCompleted: true,
    }).eligible,
    false,
  );

  // Disallowed mode (draft_pr) rejected.
  assert.equal(
    evaluatePendingTask({
      task: baseTask,
      contract: parseDispatchContract('```dispatcher\n{"mode":"draft_pr","repo":"agentpalace"}\n```'),
      config,
      activeRuns: new Map(),
      roundsUsed: 0,
      depsCompleted: true,
    }).eligible,
    false,
  );

  // Unprefixed branch (e.g. main) rejected.
  const badBranch = evaluatePendingTask({
    task: baseTask,
    contract: parseDispatchContract('```dispatcher\n{"mode":"worktree_branch","repo":"agentpalace","branch":"main"}\n```'),
    config,
    activeRuns: new Map(),
    roundsUsed: 0,
    depsCompleted: true,
  });
  assert.equal(badBranch.eligible, false);
  assert.match(badBranch.reason, /prefix/);

  // Option-like baseRef (--force) rejected.
  const badBaseRef = evaluatePendingTask({
    task: baseTask,
    contract: parseDispatchContract('```dispatcher\n{"mode":"worktree_branch","repo":"agentpalace","baseRef":"--force"}\n```'),
    config,
    activeRuns: new Map(),
    roundsUsed: 0,
    depsCompleted: true,
  });
  assert.equal(badBaseRef.eligible, false);
  assert.match(badBaseRef.reason, /baseRef/);

  // Valid mutating task has allowPush=false, maxRounds clamped to maxRoundsCap, timeoutMs clamped to maxTimeoutMs.
  const ok = evaluatePendingTask({
    task: baseTask,
    contract: parseDispatchContract(
      '```dispatcher\n{"mode":"worktree_branch","repo":"agentpalace","branch":"agent/t1","allowCommit":true,"allowPush":true,"maxRounds":999999,"timeoutMs":3000000000}\n```',
    ),
    config,
    activeRuns: new Map(),
    roundsUsed: 1,
    depsCompleted: true,
  });
  assert.equal(ok.eligible, true);
  assert.equal(ok.effectiveContract.allowCommit, true);
  assert.equal(ok.effectiveContract.allowPush, false);
  assert.equal(ok.effectiveContract.maxRounds, 4);
  assert.equal(ok.effectiveContract.timeoutMs, 120000);
});

test('evaluateInboxTask enforces repo, mode, sender allowlist, and round caps on inbox wakeups', () => {
  const config = {
    executorId: 'home-pc',
    polling: { wings: [] },
    limits: { defaultMaxRounds: 3, maxRoundsCap: 3, defaultTimeoutMs: 30000, maxTimeoutMs: 30000 },
    policy: {
      allowedCreators: [],
      allowedSenders: ['claude'],
      allowedModes: ['read_only', 'worktree_branch'],
      allowCommit: false,
      allowPush: false,
      branchPrefix: 'agent/',
    },
    repos: { agentpalace: '/repos/agentpalace' },
  };

  const taskUnmapped = {
    task_id: 'task_1',
    state: 'running',
    wing: 'wing_agentpalace',
    created_by: 'dion',
  };
  const badRepo = evaluateInboxTask({
    task: taskUnmapped,
    contract: parseDispatchContract('```dispatcher\n{"mode":"worktree_branch","repo":"unmapped"}\n```'),
    config,
    activeRuns: new Map(),
    roundsUsed: 0,
    messages: [{ message_id: 'm1', sender: 'claude' }],
  });
  assert.equal(badRepo.eligible, false);
  assert.match(badRepo.reason, /not mapped/);

  const badSender = evaluateInboxTask({
    task: taskUnmapped,
    contract: parseDispatchContract(''),
    config,
    activeRuns: new Map(),
    roundsUsed: 0,
    messages: [{ message_id: 'm2', sender: 'stranger' }],
  });
  assert.equal(badSender.eligible, false);
  assert.match(badSender.reason, /allowedSenders/);
});

test('buildBootstrapPrompt defaults missing contract mode to read_only and uses agentpalace_message_acknowledge', () => {
  const missingContractPrompt = buildBootstrapPrompt({
    task: { task_id: 'task_plain', wing: 'wing_agents', title: 'Plain task' },
    contract: {},
    harnessName: 'claude',
    trigger: 'pending',
    messageIds: [],
    claimMode: 'agent',
  });
  assert.match(missingContractPrompt, /READ-ONLY/);

  const withMsg = buildBootstrapPrompt({
    task: { task_id: 'task_abc', wing: 'wing_example', title: 'Review PR' },
    contract: { mode: 'read_only' },
    harnessName: 'codex',
    trigger: 'inbox',
    messageIds: ['msg_1', 'msg_2'],
    claimMode: 'agent',
  });
  assert.match(withMsg, /task_abc/);
  assert.match(withMsg, /msg_1, msg_2/);
  assert.match(withMsg, /agentpalace_message_acknowledge/);
  assert.doesNotMatch(withMsg, /agentpalace_message_ack\b/);
  assert.match(withMsg, /READ-ONLY/);
});

test('parseDispatchContract clamps timeoutMs to MAX_TIMEOUT_MS and ignores null numeric fields', () => {
  const desc = '```dispatcher\n{"target":"claude","maxRounds":null,"timeoutMs":3000000000,"branch":"../bad","baseRef":"--force"}\n```';
  const contract = parseDispatchContract(desc);
  assert.equal(contract.maxRounds, undefined);
  assert.equal(contract.timeoutMs, MAX_TIMEOUT_MS);
  assert.equal(contract.branch, undefined);
  assert.equal(contract.branchInvalid, true);
  assert.equal(contract.baseRef, undefined);
  assert.equal(contract.baseRefInvalid, true);
});

test('buildHarnessInvocation formats claude, codex, opencode, and custom adapters', () => {
  const claude = buildHarnessInvocation(
    { name: 'claude', type: 'claude', command: 'claude', extraArgs: ['--model', 'sonnet'], env: {} },
    { taskId: 'task_1', prompt: 'hi' },
  );
  assert.deepEqual(claude.args, ['-p', '--model', 'sonnet']);
  assert.equal(claude.promptDelivery, 'stdin');

  const codex = buildHarnessInvocation(
    { name: 'codex', type: 'codex', command: 'codex', extraArgs: ['--full-auto'], env: {} },
    { taskId: 'task_1', prompt: 'hi' },
  );
  assert.deepEqual(codex.args, ['exec', '--full-auto', '-']);
  assert.equal(codex.promptDelivery, 'stdin');

  const opencode = buildHarnessInvocation(
    {
      name: 'opencode',
      type: 'opencode',
      command: 'opencode',
      attachUrl: 'http://127.0.0.1:4096',
      extraArgs: ['--agent', 'build'],
      promptDelivery: 'stdin',
      env: {},
    },
    { taskId: 'task_1', worktreePath: '/tmp/wt', prompt: 'hi' },
  );
  assert.deepEqual(opencode.args, [
    'run',
    '--format',
    'json',
    '--attach',
    'http://127.0.0.1:4096',
    '--dir',
    '/tmp/wt',
    '--agent',
    'build',
  ]);
});

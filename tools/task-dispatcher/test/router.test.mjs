import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDispatchContract,
  resolveTargetHarness,
  evaluatePendingTask,
  buildBootstrapPrompt,
} from '../src/router.mjs';
import { buildHarnessInvocation } from '../src/harnesses.mjs';

test('parseDispatchContract parses fenced dispatcher block', () => {
  const desc = `Review PR #70.

\`\`\`dispatcher
{
  "target": "Claude",
  "mode": "worktree_branch",
  "repo": "ShotQuill",
  "executor": "home-pc",
  "maxRounds": 3,
  "allowCommit": true
}
\`\`\`
`;
  const contract = parseDispatchContract(desc);
  assert.equal(contract.target, 'claude');
  assert.equal(contract.mode, 'worktree_branch');
  assert.equal(contract.repo, 'shotquill');
  assert.equal(contract.executor, 'home-pc');
  assert.equal(contract.maxRounds, 3);
  assert.equal(contract.allowCommit, true);
  assert.equal(contract.allowPush, false);
});

test('parseDispatchContract ignores unrelated or invalid JSON blocks', () => {
  const desc = `Some task\n\`\`\`json\n{ not valid json\n\`\`\`\n\`\`\`json\n{"unrelated": true}\n\`\`\``;
  assert.deepEqual(parseDispatchContract(desc), {});
});

test('resolveTargetHarness follows precedence and skips disabled harnesses', () => {
  const enabled = { claude: { enabled: true }, codex: { enabled: true } };
  assert.equal(
    resolveTargetHarness({ owner: 'codex' }, { target: 'claude' }, enabled),
    'claude',
  );
  assert.equal(
    resolveTargetHarness({ owner: 'codex' }, {}, enabled),
    'codex',
  );
  assert.equal(
    resolveTargetHarness({ executor_affinity: 'opencode' }, {}, enabled),
    null,
  );
  assert.equal(
    resolveTargetHarness({}, { target: 'any' }, enabled),
    'claude',
  );
});

test('evaluatePendingTask enforces executor, dependencies, repo mapping, and round cap', () => {
  const config = {
    executorId: 'home-pc',
    limits: { defaultMaxRounds: 3 },
    repos: { agentpalace: '/repos/agentpalace' },
    harnesses: {
      claude: { enabled: true, maxConcurrent: 1 },
      codex: { enabled: false, maxConcurrent: 1 },
    },
  };

  const baseTask = { task_id: 'task_1', state: 'pending', owner: 'claude' };

  assert.equal(
    evaluatePendingTask({
      task: baseTask,
      contract: { executor: 'actuarius-vm' },
      config,
      activeRuns: new Map(),
      roundsUsed: 0,
      depsCompleted: true,
    }).eligible,
    false,
  );

  assert.equal(
    evaluatePendingTask({
      task: baseTask,
      contract: {},
      config,
      activeRuns: new Map(),
      roundsUsed: 0,
      depsCompleted: false,
    }).eligible,
    false,
  );

  const capped = evaluatePendingTask({
    task: baseTask,
    contract: { maxRounds: 2 },
    config,
    activeRuns: new Map(),
    roundsUsed: 2,
    depsCompleted: true,
  });
  assert.equal(capped.eligible, false);
  assert.equal(capped.capReached, true);

  const missingRepo = evaluatePendingTask({
    task: baseTask,
    contract: { mode: 'worktree_branch', repo: 'unknown' },
    config,
    activeRuns: new Map(),
    roundsUsed: 0,
    depsCompleted: true,
  });
  assert.equal(missingRepo.eligible, false);

  const ok = evaluatePendingTask({
    task: baseTask,
    contract: { mode: 'worktree_branch', repo: 'agentpalace' },
    config,
    activeRuns: new Map(),
    roundsUsed: 1,
    depsCompleted: true,
  });
  assert.equal(ok.eligible, true);
  assert.equal(ok.harnessName, 'claude');
  assert.equal(ok.repoPath, '/repos/agentpalace');
});

test('buildBootstrapPrompt keeps task authoritative, uses agentpalace_message_acknowledge, and numbers steps sequentially', () => {
  const withMsg = buildBootstrapPrompt({
    task: { task_id: 'task_abc', wing: 'wing_shotquill', title: 'Review PR' },
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

  const noMsg = buildBootstrapPrompt({
    task: { task_id: 'task_xyz', wing: 'wing_shotquill', title: 'Review PR' },
    contract: { mode: 'read_only' },
    harnessName: 'claude',
    trigger: 'pending',
    messageIds: [],
    claimMode: 'agent',
  });
  assert.match(noMsg, /\n1\. /);
  assert.match(noMsg, /\n2\. Claim task/);
  assert.match(noMsg, /\n3\. Execute only/);
  assert.match(noMsg, /\n4\. When finished/);
});

test('parseDispatchContract ignores null numeric fields and rejects unsafe branch names', () => {
  const desc = '```dispatcher\n{"target":"claude","maxRounds":null,"timeoutMs":null,"branch":"../bad"}\n```';
  const contract = parseDispatchContract(desc);
  assert.equal(contract.maxRounds, undefined);
  assert.equal(contract.timeoutMs, undefined);
  assert.equal(contract.branch, undefined);

  const safe = parseDispatchContract('```dispatcher\n{"branch":"feat/my-branch_1"}\n```');
  assert.equal(safe.branch, 'feat/my-branch_1');
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

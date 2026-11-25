import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { TaskDispatcher } from '../src/dispatcher.mjs';
import { runHarnessProcess } from '../src/process-runner.mjs';

function makeBaseConfig(tmpDir, overrides = {}) {
  return {
    executorId: 'home-pc',
    palace: { baseUrl: 'http://127.0.0.1:8775', token: '', tokenIdentity: '', requestTimeoutMs: 5000 },
    polling: { intervalMs: 15000, wings: [], watchInbox: true, watchPendingTasks: true },
    limits: {
      maxConcurrent: 2,
      defaultMaxRounds: 2,
      maxRoundsCap: 5,
      defaultTimeoutMs: 30000,
      maxTimeoutMs: 60000,
      claimMode: 'agent',
      dispatcherSuccessState: 'input_required',
      leaseSeconds: 600,
      maxSeenMessages: 5000,
      ...overrides.limits,
    },
    policy: {
      allowedCreators: [],
      allowedSenders: [],
      allowedModes: ['read_only', 'worktree_branch'],
      allowCommit: false,
      allowPush: false,
      branchPrefix: 'agent/',
      ...overrides.policy,
    },
    paths: {
      worktreeRoot: path.join(tmpDir, 'worktrees'),
      logDir: path.join(tmpDir, 'logs'),
      stateFile: path.join(tmpDir, 'state.json'),
    },
    repos: { agentpalace: tmpDir, ...overrides.repos },
    harnesses: {
      claude: {
        name: 'claude',
        enabled: true,
        type: 'claude',
        command: 'claude',
        extraArgs: [],
        actorAliases: [],
        maxConcurrent: 1,
        env: {},
      },
      codex: {
        name: 'codex',
        enabled: true,
        type: 'codex',
        command: 'codex',
        extraArgs: [],
        actorAliases: [],
        maxConcurrent: 1,
        env: {},
      },
    },
    notifications: { webhookUrl: '' },
  };
}

test('TaskDispatcher dispatches pending worktree task, skips unfinished deps, and verifies post-exit state', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-'));
  try {
    const tasks = new Map([
      [
        'task_dep',
        { task_id: 'task_dep', title: 'Dep', description: '', state: 'running', revision: 1, wing: 'wing_agentpalace', dependencies: [] },
      ],
      [
        'task_blocked',
        {
          task_id: 'task_blocked',
          title: 'Blocked',
          description: '```dispatcher\n{"target":"claude"}\n```',
          state: 'pending',
          revision: 1,
          wing: 'wing_agentpalace',
          dependencies: ['task_dep'],
        },
      ],
      [
        'task_ready',
        {
          task_id: 'task_ready',
          title: 'Ready',
          description: '```dispatcher\n{"target":"codex","mode":"worktree_branch","repo":"agentpalace"}\n```',
          state: 'pending',
          revision: 1,
          wing: 'wing_agentpalace',
          dependencies: [],
        },
      ],
    ]);

    const worktreeCalls = [];
    const runnerCalls = [];

    const client = {
      async listTasks() {
        return { tasks: [tasks.get('task_blocked'), tasks.get('task_ready')] };
      },
      async getTask(id) {
        return tasks.get(id);
      },
      async readInbox() {
        return { messages: [] };
      },
    };

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir),
      client,
      worktreeManager: {
        async ensureWorktree(opts) {
          worktreeCalls.push(opts);
          return { worktreePath: path.join(tmpDir, 'wt-ready'), branchName: 'agent/task_ready', reused: false };
        },
      },
      runner: async (opts) => {
        runnerCalls.push(opts);
        tasks.get('task_ready').state = 'completed';
        tasks.get('task_ready').revision = 2;
        return { exitCode: 0, timedOut: false, durationMs: 50, logPath: opts.logPath };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    await dispatcher.loadState();
    const launched = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();

    assert.equal(launched.length, 1);
    assert.equal(launched[0].taskId, 'task_ready');
    assert.equal(launched[0].harnessName, 'codex');
    assert.equal(worktreeCalls.length, 1);
    assert.equal(worktreeCalls[0].branchPrefix, 'agent/');
    assert.equal(runnerCalls.length, 1);
    assert.equal(runnerCalls[0].cwd, path.join(tmpDir, 'wt-ready'));
    assert.equal(dispatcher.state.roundsByTask.task_ready, 1);
    assert.equal(dispatcher.state.managedBranches.task_ready, 'agent/task_ready');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher wakes harness on unread inbox messages and enforces ping-pong maxRounds cap', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-inbox-'));
  try {
    const task = {
      task_id: 'task_discuss',
      title: 'Back and forth',
      description: '```dispatcher\n{"maxRounds": 2}\n```',
      state: 'input_required',
      revision: 3,
      wing: 'wing_agents',
      dependencies: [],
    };

    let inboxMessages = [{ message_id: 'msg_1', task_id: 'task_discuss', recipient: 'claude', sender: 'codex' }];
    const runs = [];

    const client = {
      async listTasks() {
        return { tasks: [] };
      },
      async getTask() {
        return task;
      },
      async readInbox({ recipient }) {
        return { messages: inboxMessages.filter((m) => m.recipient === recipient) };
      },
    };

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir),
      client,
      runner: async (opts) => {
        runs.push(opts);
        return { exitCode: 0, timedOut: false, durationMs: 10, logPath: opts.logPath };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    await dispatcher.loadState();

    // Round 1: wakes claude for msg_1.
    const r1 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r1.length, 1);
    assert.deepEqual(r1[0].messageIds, ['msg_1']);

    // Round 2: new message arrives for codex; wakes codex.
    inboxMessages = [{ message_id: 'msg_2', task_id: 'task_discuss', recipient: 'codex', sender: 'claude' }];
    const r2 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r2.length, 1);
    assert.equal(r2[0].harnessName, 'codex');

    // Round 3 & 4: cap (2) is reached -> must NOT wake claude again, and notify at most once.
    inboxMessages = [{ message_id: 'msg_3', task_id: 'task_discuss', recipient: 'claude', sender: 'codex' }];
    let notifyCount = 0;
    dispatcher._notify = async () => {
      notifyCount += 1;
    };
    const r3 = await dispatcher.pollOnce();
    const r4 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r3.length, 0);
    assert.equal(r4.length, 0);
    assert.equal(notifyCount, 1);
    assert.equal(runs.length, 2);

    // Resetting task clears round cap so a subsequent poll wakes again.
    await dispatcher.resetTask('task_discuss');
    const r5 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r5.length, 1);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher inbox path rejects unmapped repo before touching worktrees', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-inb-repo-'));
  try {
    const task = {
      task_id: 'task_bad_inbox',
      title: 'Unmapped repo',
      description: '```dispatcher\n{"mode":"worktree_branch","repo":"unmapped"}\n```',
      state: 'running',
      revision: 1,
      wing: 'wing_agents',
      created_by: 'dion',
      dependencies: [],
    };
    let worktreeCalled = false;
    let runnerCalled = false;

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir),
      client: {
        async listTasks() {
          return { tasks: [] };
        },
        async getTask() {
          return task;
        },
        async readInbox({ recipient }) {
          return recipient === 'claude'
            ? { messages: [{ message_id: 'm1', task_id: 'task_bad_inbox', recipient: 'claude', sender: 'dion' }] }
            : { messages: [] };
        },
      },
      worktreeManager: {
        async ensureWorktree() {
          worktreeCalled = true;
          return { worktreePath: tmpDir, branchName: 'agent/x', reused: false };
        },
      },
      runner: async () => {
        runnerCalled = true;
        return { exitCode: 0, timedOut: false };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    await dispatcher.loadState();
    const launched = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(launched.length, 0);
    assert.equal(worktreeCalled, false);
    assert.equal(runnerCalled, false);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher claimMode=dispatcher reconciles clean exit using result_created events', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-claim-'));
  try {
    const taskWithResult = {
      task_id: 'task_res',
      title: 'With result',
      description: '```dispatcher\n{"target":"claude"}\n```',
      state: 'pending',
      revision: 1,
      wing: 'wing_agentpalace',
      dependencies: [],
    };
    const taskNoResult = {
      task_id: 'task_nores',
      title: 'Without result',
      description: '```dispatcher\n{"target":"codex"}\n```',
      state: 'pending',
      revision: 1,
      wing: 'wing_agentpalace',
      dependencies: [],
    };
    const tasks = new Map([
      ['task_res', taskWithResult],
      ['task_nores', taskNoResult],
    ]);
    const eventsByTask = { task_res: [], task_nores: [] };
    const transitions = [];

    const client = {
      async listTasks() {
        return { tasks: [taskWithResult, taskNoResult].filter((t) => t.state === 'pending') };
      },
      async getTask(id) {
        return { ...tasks.get(id) };
      },
      async readInbox() {
        return { messages: [] };
      },
      async listEvents({ taskId }) {
        return { events: eventsByTask[taskId] ?? [], next_cursor: null };
      },
      async claimTask(id) {
        const t = tasks.get(id);
        t.state = 'running';
        t.revision += 1;
        return { ...t };
      },
      async transitionTask(id, { state, details }) {
        const t = tasks.get(id);
        t.state = state;
        t.revision += 1;
        transitions.push({ id, state, details });
        return { ...t };
      },
    };

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir, { limits: { claimMode: 'dispatcher', dispatcherSuccessState: 'input_required' } }),
      client,
      runner: async (opts) => {
        if (opts.prompt.includes('task_res')) {
          eventsByTask.task_res.push({ event_id: 'ev_1', entity_id: 'result_1', event_type: 'result_created' });
        }
        return { exitCode: 0, timedOut: false, durationMs: 10, logPath: opts.logPath };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    await dispatcher.loadState();
    await dispatcher.pollOnce();
    await dispatcher.waitForInflight();

    assert.equal(taskWithResult.state, 'input_required');
    assert.equal(taskNoResult.state, 'pending');
    assert.equal(transitions.length, 2);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher stop() awaits in-flight pollOnce and prevents post-stop launches', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-stop-'));
  try {
    let releaseList;
    const listGate = new Promise((r) => {
      releaseList = r;
    });
    let runnerCalled = false;

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir),
      client: {
        async listTasks() {
          await listGate;
          return {
            tasks: [{ task_id: 'task_late', title: 'Late', description: '', state: 'pending', revision: 1, wing: 'wing_agentpalace', dependencies: [] }],
          };
        },
        async getTask() {
          return { task_id: 'task_late', title: 'Late', description: '```dispatcher\n{"target":"claude"}\n```', state: 'pending', revision: 1, wing: 'wing_agentpalace', dependencies: [] };
        },
        async readInbox() {
          return { messages: [] };
        },
      },
      runner: async () => {
        runnerCalled = true;
        return { exitCode: 0, timedOut: false };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    const pollPromise = dispatcher.pollOnce();
    const stopPromise = dispatcher.stop();
    releaseList();
    await Promise.all([pollPromise, stopPromise]);
    assert.equal(runnerCalled, false);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher fails closed on corrupt state file and serializes atomic saveState + prunes seenMessageIds', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-state-'));
  try {
    const cfg = makeBaseConfig(tmpDir, { limits: { maxSeenMessages: 100 } });
    await fs.writeFile(cfg.paths.stateFile, '{corrupt json', 'utf8');

    const badDispatcher = new TaskDispatcher({
      config: cfg,
      client: {},
      logger: { log() {}, warn() {}, error() {} },
    });
    await assert.rejects(() => badDispatcher.loadState());
    // Corrupt file must still exist untouched.
    assert.equal(await fs.readFile(cfg.paths.stateFile, 'utf8'), '{corrupt json');

    await fs.rm(cfg.paths.stateFile, { force: true });
    const goodDispatcher = new TaskDispatcher({
      config: cfg,
      client: {},
      logger: { log() {}, warn() {}, error() {} },
    });
    await goodDispatcher.loadState();
    for (let i = 0; i < 150; i++) {
      goodDispatcher.state.seenMessageIds[`m_${i}`] = `2026-11-25T00:00:${String(i).padStart(2, '0')}Z`;
    }
    await Promise.all([goodDispatcher.saveState(), goodDispatcher.saveState()]);
    const saved = JSON.parse(await fs.readFile(cfg.paths.stateFile, 'utf8'));
    assert.equal(Object.keys(saved.seenMessageIds).length, 100);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TaskDispatcher paginates listTasks via next_cursor and retries inbox messages after crash', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-disp-page-'));
  try {
    const taskPage2 = {
      task_id: 'task_p2',
      title: 'Page 2 task',
      description: '```dispatcher\n{"target":"claude"}\n```',
      state: 'pending',
      revision: 1,
      wing: 'wing_agents',
      dependencies: [],
    };
    const inboxTask = {
      task_id: 'task_retry',
      title: 'Retry inbox task',
      description: '```dispatcher\n{"maxRounds": 3}\n```',
      state: 'input_required',
      revision: 1,
      wing: 'wing_agents',
      dependencies: [],
    };

    let attempt = 0;
    const client = {
      async listTasks({ cursor }) {
        if (!cursor) return { tasks: [], next_cursor: 'page2' };
        return { tasks: [taskPage2], next_cursor: null };
      },
      async getTask(id) {
        return id === 'task_p2' ? taskPage2 : inboxTask;
      },
      async readInbox({ recipient }) {
        if (recipient !== 'codex') return { messages: [] };
        return { messages: [{ message_id: 'msg_crash', task_id: 'task_retry', recipient: 'codex', sender: 'claude' }] };
      },
    };

    const dispatcher = new TaskDispatcher({
      config: makeBaseConfig(tmpDir),
      client,
      runner: async (opts) => {
        attempt += 1;
        if (opts.prompt.includes('msg_crash') && attempt <= 2) {
          return { exitCode: 1, timedOut: false, durationMs: 5, logPath: opts.logPath };
        }
        return { exitCode: 0, timedOut: false, durationMs: 5, logPath: opts.logPath };
      },
      logger: { log() {}, warn() {}, error() {} },
    });

    await dispatcher.loadState();
    const first = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(first.length, 2);
    assert.equal(dispatcher.state.seenMessageIds.msg_crash, undefined);

    taskPage2.state = 'completed';
    const second = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(second.length, 1);
    assert.equal(second[0].taskId, 'task_retry');
    assert.ok(dispatcher.state.seenMessageIds.msg_crash);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runHarnessProcess handles immediate exit / broken stdin pipe without crashing', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-epipe-'));
  try {
    const res = await runHarnessProcess({
      command: process.execPath,
      args: ['-e', 'process.exit(0)'],
      cwd: tmpDir,
      prompt: 'x'.repeat(256 * 1024),
      promptDelivery: 'stdin',
      timeoutMs: 5000,
      logPath: path.join(tmpDir, 'epipe.log'),
    });
    assert.equal(res.exitCode, 0);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runHarnessProcess clamps >2^31-1 timeouts, preserves spaces in args, and kills process on timeout', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-proc-'));
  try {
    const clampedOk = await runHarnessProcess({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => process.exit(0), 200);'],
      cwd: tmpDir,
      prompt: '',
      promptDelivery: 'stdin',
      timeoutMs: 3_000_000_000,
      logPath: path.join(tmpDir, 'clamped.log'),
    });
    assert.equal(clampedOk.exitCode, 0);
    assert.equal(clampedOk.timedOut, false);

    const ok = await runHarnessProcess({
      command: process.execPath,
      args: [
        '-e',
        'let d=""; process.stdin.on("data",c=>d+=c); process.stdin.on("end",()=>process.stdout.write("ARG:" + process.argv[1] + "|STDIN:" + d.trim()));',
        'Bash(git *),Bash(node *)',
      ],
      cwd: tmpDir,
      prompt: 'hello-palace\n',
      promptDelivery: 'stdin',
      timeoutMs: 5000,
      logPath: path.join(tmpDir, 'ok.log'),
    });
    assert.equal(ok.exitCode, 0);
    assert.equal(ok.timedOut, false);
    assert.equal(ok.stdoutTail, 'ARG:Bash(git *),Bash(node *)|STDIN:hello-palace');

    const timedOut = await runHarnessProcess({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 30000);'],
      cwd: tmpDir,
      prompt: '',
      promptDelivery: 'stdin',
      timeoutMs: 250,
      logPath: path.join(tmpDir, 'timeout.log'),
    });
    assert.equal(timedOut.timedOut, true);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

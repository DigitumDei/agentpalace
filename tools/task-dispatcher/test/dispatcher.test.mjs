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
    palace: { baseUrl: 'http://127.0.0.1:8765', token: '', requestTimeoutMs: 5000 },
    polling: { intervalMs: 15000, wings: [], watchInbox: true, watchPendingTasks: true },
    limits: {
      maxConcurrent: 2,
      defaultMaxRounds: 2,
      defaultTimeoutMs: 30000,
      claimMode: 'agent',
      leaseSeconds: 600,
      ...overrides.limits,
    },
    paths: {
      worktreeRoot: path.join(tmpDir, 'worktrees'),
      logDir: path.join(tmpDir, 'logs'),
      stateFile: path.join(tmpDir, 'state.json'),
    },
    repos: { agentpalace: tmpDir },
    harnesses: {
      claude: {
        name: 'claude',
        enabled: true,
        type: 'claude',
        command: 'claude',
        extraArgs: [],
        maxConcurrent: 1,
        env: {},
      },
      codex: {
        name: 'codex',
        enabled: true,
        type: 'codex',
        command: 'codex',
        extraArgs: [],
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
        // Simulate the agent transitioning the task to completed via MCP.
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
    assert.equal(runnerCalls.length, 1);
    assert.equal(runnerCalls[0].cwd, path.join(tmpDir, 'wt-ready'));
    assert.equal(dispatcher.state.roundsByTask.task_ready, 1);
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

    let inboxMessages = [{ message_id: 'msg_1', task_id: 'task_discuss', recipient: 'claude' }];
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
    inboxMessages = [{ message_id: 'msg_2', task_id: 'task_discuss', recipient: 'codex' }];
    const r2 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r2.length, 1);
    assert.equal(r2[0].harnessName, 'codex');

    // Round 3: cap (2) is reached -> must NOT wake claude again.
    inboxMessages = [{ message_id: 'msg_3', task_id: 'task_discuss', recipient: 'claude' }];
    const r3 = await dispatcher.pollOnce();
    await dispatcher.waitForInflight();
    assert.equal(r3.length, 0);
    assert.equal(runs.length, 2);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runHarnessProcess delivers prompt via stdin and kills process on timeout', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-proc-'));
  try {
    const ok = await runHarnessProcess({
      command: process.execPath,
      args: ['-e', 'let d=""; process.stdin.on("data",c=>d+=c); process.stdin.on("end",()=>process.stdout.write("ECHO:"+d.trim()));'],
      cwd: tmpDir,
      prompt: 'hello-palace\n',
      promptDelivery: 'stdin',
      timeoutMs: 5000,
      logPath: path.join(tmpDir, 'ok.log'),
    });
    assert.equal(ok.exitCode, 0);
    assert.equal(ok.timedOut, false);
    assert.equal(ok.stdoutTail, 'ECHO:hello-palace');

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

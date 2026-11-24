import fs from 'node:fs/promises';
import path from 'node:path';
import {
  parseDispatchContract,
  isTerminalState,
  evaluatePendingTask,
  buildBootstrapPrompt,
} from './router.mjs';
import { ensureWorktree, sanitizeSlug } from './worktree.mjs';
import { buildHarnessInvocation } from './harnesses.mjs';
import { runHarnessProcess } from './process-runner.mjs';

export class TaskDispatcher {
  constructor({
    config,
    client,
    runner = runHarnessProcess,
    worktreeManager = { ensureWorktree },
    logger = console,
    dryRun = false,
  }) {
    this.config = config;
    this.client = client;
    this.runner = runner;
    this.worktreeManager = worktreeManager;
    this.logger = logger;
    this.dryRun = dryRun;

    /** @type {Map<string, { harnessName: string, startedAt: number, trigger: string }>} */
    this.activeRuns = new Map();
    /** @type {Map<string, number>} */
    this.harnessActiveCount = new Map();
    /** @type {Map<string, { revision: number, task: any }>} */
    this.taskCache = new Map();
    /** @type {{ roundsByTask: Record<string, number>, seenMessageIds: Record<string, string> }} */
    this.state = { roundsByTask: {}, seenMessageIds: {} };

    this._stopRequested = false;
    this._timer = null;
    this._inflightPromises = new Set();
  }

  async loadState() {
    try {
      const raw = await fs.readFile(this.config.paths.stateFile, 'utf8');
      const parsed = JSON.parse(raw);
      this.state = {
        roundsByTask: parsed.roundsByTask && typeof parsed.roundsByTask === 'object' ? parsed.roundsByTask : {},
        seenMessageIds: parsed.seenMessageIds && typeof parsed.seenMessageIds === 'object' ? parsed.seenMessageIds : {},
      };
    } catch {
      this.state = { roundsByTask: {}, seenMessageIds: {} };
    }
  }

  async saveState() {
    if (this.dryRun) return;
    await fs.mkdir(path.dirname(this.config.paths.stateFile), { recursive: true });
    await fs.writeFile(this.config.paths.stateFile, JSON.stringify(this.state, null, 2) + '\n', 'utf8');
  }

  _canRunHarness(harnessName) {
    if (this.activeRuns.size >= this.config.limits.maxConcurrent) {
      return false;
    }
    const harness = this.config.harnesses[harnessName];
    if (!harness || !harness.enabled) return false;
    const current = this.harnessActiveCount.get(harnessName) ?? 0;
    return current < harness.maxConcurrent;
  }

  async _getFullTask(taskId, expectedRevision) {
    const cached = this.taskCache.get(taskId);
    if (cached && expectedRevision !== undefined && cached.revision === expectedRevision) {
      return cached.task;
    }
    const full = await this.client.getTask(taskId);
    this.taskCache.set(taskId, { revision: full.revision, task: full });
    return full;
  }

  async _areDependenciesCompleted(task) {
    const deps = Array.isArray(task.dependencies) ? task.dependencies : [];
    for (const depId of deps) {
      try {
        const dep = await this.client.getTask(depId);
        if (dep.state !== 'completed') {
          return false;
        }
      } catch {
        return false;
      }
    }
    return true;
  }

  async _notify(text) {
    const url = this.config.notifications?.webhookUrl;
    if (!url || this.dryRun) return;
    try {
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text, text }),
      });
    } catch (err) {
      this.logger.warn(`[dispatcher] Webhook notification failed: ${err.message}`);
    }
  }

  /**
   * Perform a single poll cycle across pending tasks and enabled harness inboxes.
   * Returns a summary of dispatches launched or planned (in dry-run mode).
   */
  async pollOnce() {
    const dispatched = [];

    if (this.config.polling.watchPendingTasks) {
      const wings = this.config.polling.wings.length > 0 ? this.config.polling.wings : [undefined];
      for (const wing of wings) {
        const page = await this.client.listTasks({ state: 'pending', wing, limit: 50 });
        for (const summary of page.tasks ?? []) {
          if (this.activeRuns.size >= this.config.limits.maxConcurrent) break;
          if (this.activeRuns.has(summary.task_id)) continue;

          const task = await this._getFullTask(summary.task_id, summary.revision);
          const contract = parseDispatchContract(task.description);
          const depsCompleted = await this._areDependenciesCompleted(task);
          const roundsUsed = this.state.roundsByTask[task.task_id] ?? 0;

          const decision = evaluatePendingTask({
            task,
            contract,
            config: this.config,
            activeRuns: this.activeRuns,
            roundsUsed,
            depsCompleted,
          });

          if (!decision.eligible) {
            if (decision.capReached) {
              this.logger.warn(`[dispatcher] Skipping ${task.task_id}: ${decision.reason}`);
            }
            continue;
          }

          if (!this._canRunHarness(decision.harnessName)) {
            continue;
          }

          dispatched.push(
            this._launch({
              task,
              contract,
              harnessName: decision.harnessName,
              repoPath: decision.repoPath,
              trigger: 'pending',
              messageIds: [],
            }),
          );
        }
      }
    }

    if (this.config.polling.watchInbox) {
      const enabledHarnesses = Object.values(this.config.harnesses).filter((h) => h.enabled);
      for (const harness of enabledHarnesses) {
        if (!this._canRunHarness(harness.name)) continue;

        const inbox = await this.client.readInbox({
          recipient: harness.name,
          unacknowledgedOnly: true,
          limit: 50,
        });

        // Group unread, unseen messages by task_id.
        const byTask = new Map();
        for (const msg of inbox.messages ?? []) {
          if (this.state.seenMessageIds[msg.message_id]) continue;
          const list = byTask.get(msg.task_id) ?? [];
          list.push(msg);
          byTask.set(msg.task_id, list);
        }

        for (const [taskId, messages] of byTask.entries()) {
          if (!this._canRunHarness(harness.name)) break;
          if (this.activeRuns.has(taskId)) continue;

          let task;
          try {
            task = await this.client.getTask(taskId);
          } catch {
            continue;
          }

          if (isTerminalState(task.state)) {
            continue;
          }

          const contract = parseDispatchContract(task.description);
          if (contract.executor && contract.executor !== this.config.executorId) {
            continue;
          }

          const maxRounds = contract.maxRounds ?? this.config.limits.defaultMaxRounds;
          const roundsUsed = this.state.roundsByTask[taskId] ?? 0;
          if (roundsUsed >= maxRounds) {
            this.logger.warn(
              `[dispatcher] Ping-pong cap reached for ${taskId} (${roundsUsed}/${maxRounds}); leaving unread messages for human review.`,
            );
            await this._notify(
              `[AgentPalace Dispatcher] Task \`${taskId}\` reached max rounds (${maxRounds}) with unread messages for \`${harness.name}\`. Human input needed.`,
            );
            continue;
          }

          const repoPath = contract.repo ? this.config.repos[contract.repo] : undefined;
          const messageIds = messages.map((m) => m.message_id);

          dispatched.push(
            this._launch({
              task,
              contract,
              harnessName: harness.name,
              repoPath,
              trigger: 'inbox',
              messageIds,
            }),
          );
        }
      }
    }

    return dispatched;
  }

  _launch({ task, contract, harnessName, repoPath, trigger, messageIds }) {
    const info = {
      taskId: task.task_id,
      harnessName,
      trigger,
      messageIds,
      dryRun: this.dryRun,
    };

    if (this.dryRun) {
      this.logger.log(
        `[dispatcher][dry-run] Would dispatch ${task.task_id} (${task.title}) -> ${harnessName} [${trigger}]`,
      );
      return info;
    }

    this.activeRuns.set(task.task_id, { harnessName, startedAt: Date.now(), trigger });
    this.harnessActiveCount.set(harnessName, (this.harnessActiveCount.get(harnessName) ?? 0) + 1);

    const promise = this._executeRun({ task, contract, harnessName, repoPath, trigger, messageIds })
      .catch((err) => {
        this.logger.error(`[dispatcher] Unhandled error running ${task.task_id}: ${err.message}`);
      })
      .finally(() => {
        this.activeRuns.delete(task.task_id);
        const nextCount = Math.max(0, (this.harnessActiveCount.get(harnessName) ?? 1) - 1);
        this.harnessActiveCount.set(harnessName, nextCount);
        this._inflightPromises.delete(promise);
      });

    this._inflightPromises.add(promise);
    return info;
  }

  async _executeRun({ task, contract, harnessName, repoPath, trigger, messageIds }) {
    const harness = this.config.harnesses[harnessName];
    let claimedTask = task;
    let leaseTimer = null;

    try {
      // Optional dispatcher-owned claim + lease renewal heartbeat.
      if (this.config.limits.claimMode === 'dispatcher' && task.state === 'pending') {
        claimedTask = await this.client.claimTask(task.task_id, {
          expectedRevision: task.revision,
          leaseSeconds: this.config.limits.leaseSeconds,
          worker: harnessName,
        });
        const renewEveryMs = Math.max(15000, Math.floor((this.config.limits.leaseSeconds * 1000) / 2));
        leaseTimer = setInterval(async () => {
          try {
            claimedTask = await this.client.renewTask(claimedTask.task_id, {
              expectedRevision: claimedTask.revision,
              leaseSeconds: this.config.limits.leaseSeconds,
              worker: harnessName,
            });
          } catch (err) {
            this.logger.warn(`[dispatcher] Lease renewal failed for ${task.task_id}: ${err.message}`);
          }
        }, renewEveryMs);
        leaseTimer.unref?.();
      }

      // Prepare working directory (isolated git worktree for mutating modes).
      let cwd = repoPath || process.cwd();
      let worktreePath = null;
      if (contract.mode === 'worktree_branch' || contract.mode === 'draft_pr') {
        const wt = await this.worktreeManager.ensureWorktree({
          repoPath,
          worktreeRoot: this.config.paths.worktreeRoot,
          taskId: task.task_id,
          branch: contract.branch,
          baseRef: contract.baseRef || 'HEAD',
        });
        cwd = wt.worktreePath;
        worktreePath = wt.worktreePath;
      }

      // Record round and mark triggering messages as dispatched so they don't re-fire concurrently.
      this.state.roundsByTask[task.task_id] = (this.state.roundsByTask[task.task_id] ?? 0) + 1;
      for (const id of messageIds) {
        this.state.seenMessageIds[id] = new Date().toISOString();
      }
      await this.saveState();

      const prompt = buildBootstrapPrompt({
        task: claimedTask,
        contract,
        harnessName,
        worktreePath,
        trigger,
        messageIds,
        claimMode: this.config.limits.claimMode,
      });

      const invocation = buildHarnessInvocation(harness, {
        taskId: task.task_id,
        worktreePath,
        prompt,
      });

      const logPath = path.join(
        this.config.paths.logDir,
        `${sanitizeSlug(task.task_id)}-${Date.now()}.log`,
      );
      const timeoutMs = contract.timeoutMs ?? harness.timeoutMs ?? this.config.limits.defaultTimeoutMs;

      this.logger.log(
        `[dispatcher] Launching ${harnessName} for ${task.task_id} (${trigger}, round ${this.state.roundsByTask[task.task_id]}) in ${cwd}`,
      );

      const runResult = await this.runner({
        command: invocation.command,
        args: invocation.args,
        cwd,
        env: invocation.env,
        prompt: invocation.prompt,
        promptDelivery: invocation.promptDelivery,
        timeoutMs,
        logPath,
      });

      // Authoritative post-exit verification (per docs/Agent-Task-Handoffs.md):
      // Process exit 0 alone is NOT proof of task completion.
      let afterTask = null;
      try {
        afterTask = await this.client.getTask(task.task_id);
        this.taskCache.set(task.task_id, { revision: afterTask.revision, task: afterTask });
      } catch (err) {
        this.logger.warn(`[dispatcher] Post-exit task fetch failed for ${task.task_id}: ${err.message}`);
      }

      const finalState = afterTask?.state ?? 'unknown';
      this.logger.log(
        `[dispatcher] Finished ${task.task_id} (${harnessName}): exit=${runResult.exitCode}, timedOut=${runResult.timedOut}, authoritativeState=${finalState}, log=${runResult.logPath}`,
      );

      if (runResult.exitCode === 0 && afterTask && afterTask.state === task.state && trigger === 'pending') {
        this.logger.warn(
          `[dispatcher] Warning: ${harnessName} exited 0 on ${task.task_id}, but task state remained "${afterTask.state}". Check ${runResult.logPath}.`,
        );
      }

      if (finalState === 'completed' || finalState === 'input_required' || finalState === 'failed' || runResult.timedOut) {
        await this._notify(
          `[AgentPalace Dispatcher] \`${task.task_id}\` (${task.title}) -> **${finalState}** via \`${harnessName}\` (exit ${runResult.exitCode})`,
        );
      }
    } finally {
      if (leaseTimer) clearInterval(leaseTimer);
    }
  }

  async waitForInflight() {
    await Promise.allSettled([...this._inflightPromises]);
  }

  async start() {
    await this.loadState();
    this.logger.log(
      `[dispatcher] Starting on executor="${this.config.executorId}" polling ${this.config.palace.baseUrl} every ${this.config.polling.intervalMs}ms (dryRun=${this.dryRun})`,
    );

    const tick = async () => {
      if (this._stopRequested) return;
      try {
        await this.pollOnce();
      } catch (err) {
        this.logger.error(`[dispatcher] Poll error: ${err.message}`);
      }
      if (!this._stopRequested) {
        this._timer = setTimeout(tick, this.config.polling.intervalMs);
      }
    };

    await tick();
  }

  async stop() {
    this._stopRequested = true;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    await this.waitForInflight();
  }
}

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { MAX_TIMEOUT_MS } from './config.mjs';
import {
  parseDispatchContract,
  evaluatePendingTask,
  evaluateInboxTask,
  buildBootstrapPrompt,
} from './router.mjs';
import { ensureWorktree, sanitizeSlug } from './worktree.mjs';
import { buildHarnessInvocation } from './harnesses.mjs';
import { runHarnessProcess, killProcessTree } from './process-runner.mjs';

function emptyState() {
  return {
    roundsByTask: {},
    seenMessageIds: {},
    notifiedRoundCapByTask: {},
    managedBranches: {},
    resetAtByTask: {},
  };
}

function parseTokenTimestamp(token) {
  if (typeof token !== 'string') return 0;
  const colon = token.indexOf(':');
  const num = Number(colon >= 0 ? token.slice(0, colon) : token);
  return Number.isFinite(num) ? num : 0;
}

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
    /** @type {{ roundsByTask: Record<string, number>, seenMessageIds: Record<string, string>, notifiedRoundCapByTask: Record<string, string>, managedBranches: Record<string, string>, resetAtByTask: Record<string, string> }} */
    this.state = emptyState();

    this._knownResetAtByTask = {};
    this._stopRequested = false;
    this._timer = null;
    this._inflightPromises = new Set();
    this._activePollPromise = null;
    this._activeChildren = new Set();
    this._saveQueue = Promise.resolve();
    this._loggedSkips = new Map();
  }

  async _loadStateFileOnly() {
    let raw;
    try {
      raw = await fs.readFile(this.config.paths.stateFile, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        this.state = emptyState();
        this._knownResetAtByTask = {};
        return;
      }
      this.logger.error(`[dispatcher] Failed to read state file "${this.config.paths.stateFile}": ${err.message}`);
      throw err;
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      this.logger.error(
        `[dispatcher] Corrupt state file "${this.config.paths.stateFile}" (${err.message}). Preserving file and refusing to reset caps.`,
      );
      throw err;
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      const err = new Error(`State file "${this.config.paths.stateFile}" must contain a JSON object.`);
      this.logger.error(`[dispatcher] ${err.message}`);
      throw err;
    }

    this.state = {
      roundsByTask: parsed.roundsByTask && typeof parsed.roundsByTask === 'object' ? parsed.roundsByTask : {},
      seenMessageIds: parsed.seenMessageIds && typeof parsed.seenMessageIds === 'object' ? parsed.seenMessageIds : {},
      notifiedRoundCapByTask:
        parsed.notifiedRoundCapByTask && typeof parsed.notifiedRoundCapByTask === 'object'
          ? parsed.notifiedRoundCapByTask
          : {},
      managedBranches:
        parsed.managedBranches && typeof parsed.managedBranches === 'object' ? parsed.managedBranches : {},
      resetAtByTask: parsed.resetAtByTask && typeof parsed.resetAtByTask === 'object' ? parsed.resetAtByTask : {},
    };
    this._knownResetAtByTask = { ...this.state.resetAtByTask };
  }

  async loadState() {
    await this._loadStateFileOnly();
    await this._reconcileDiskResets({ skipStateFile: true });
  }

  _applyResetToken(taskId, token) {
    if (typeof taskId !== 'string' || !taskId || typeof token !== 'string' || !token) {
      return false;
    }
    const prev = this._knownResetAtByTask[taskId];
    if (prev === token) {
      return false;
    }
    if (prev && parseTokenTimestamp(token) < parseTokenTimestamp(prev)) {
      return false;
    }
    delete this.state.roundsByTask[taskId];
    delete this.state.notifiedRoundCapByTask[taskId];
    this._loggedSkips.delete(taskId);
    this.state.resetAtByTask[taskId] = token;
    this._knownResetAtByTask[taskId] = token;
    return true;
  }

  /**
   * Reconcile external `--reset-task` actions (from `stateFile.resetAtByTask` or
   * drop-in `${stateFile}.reset.*.json` markers) into this instance's memory so
   * a running dispatcher picks up resets and never overwrites them on its next save.
   */
  async _reconcileDiskResets({ skipStateFile = false } = {}) {
    let changed = false;
    const stateFile = this.config.paths.stateFile;

    if (!skipStateFile) {
      try {
        const raw = await fs.readFile(stateFile, 'utf8');
        const disk = JSON.parse(raw);
        if (disk?.resetAtByTask && typeof disk.resetAtByTask === 'object') {
          for (const [taskId, token] of Object.entries(disk.resetAtByTask)) {
            if (this._applyResetToken(taskId, token)) {
              changed = true;
            }
          }
        }
      } catch {
        // Ignore ENOENT or transient read/parse while another process renames the file.
      }
    }

    const dir = path.dirname(stateFile);
    const markerPrefix = `${path.basename(stateFile)}.reset.`;
    let entries = [];
    try {
      entries = await fs.readdir(dir);
    } catch {
      return changed;
    }

    for (const name of entries) {
      if (!name.startsWith(markerPrefix) || !name.endsWith('.json')) continue;
      const markerPath = path.join(dir, name);
      try {
        const raw = await fs.readFile(markerPath, 'utf8');
        const marker = JSON.parse(raw);
        if (marker && typeof marker.taskId === 'string' && typeof marker.token === 'string') {
          if (this._applyResetToken(marker.taskId, marker.token)) {
            changed = true;
          }
          await fs.rm(markerPath, { force: true }).catch(() => {});
        }
      } catch {
        // Ignore transient partial marker writes; next poll/save will pick it up.
      }
    }

    return changed;
  }

  _pruneSeenMessageIds() {
    const maxSeen = this.config.limits?.maxSeenMessages ?? 5000;
    const entries = Object.entries(this.state.seenMessageIds);
    if (entries.length > maxSeen) {
      entries.sort((a, b) => String(a[1]).localeCompare(String(b[1])));
      this.state.seenMessageIds = Object.fromEntries(entries.slice(entries.length - maxSeen));
    }

    const resetEntries = Object.entries(this.state.resetAtByTask);
    if (resetEntries.length > 1000) {
      resetEntries.sort((a, b) => parseTokenTimestamp(a[1]) - parseTokenTimestamp(b[1]));
      this.state.resetAtByTask = Object.fromEntries(resetEntries.slice(resetEntries.length - 1000));
    }
  }

  async _writeStateAtomic() {
    this._pruneSeenMessageIds();
    const stateFile = this.config.paths.stateFile;
    const dir = path.dirname(stateFile);
    await fs.mkdir(dir, { recursive: true });
    const snapshot = JSON.stringify(this.state, null, 2) + '\n';
    const tmpPath = `${stateFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(tmpPath, snapshot, 'utf8');
      await fs.rename(tmpPath, stateFile);
    } catch (err) {
      await fs.rm(tmpPath, { force: true }).catch(() => {});
      throw err;
    }
  }

  async saveState() {
    if (this.dryRun) return;

    const writeOp = async () => {
      await this._reconcileDiskResets();
      await this._writeStateAtomic();
    };

    const next = this._saveQueue.then(writeOp, writeOp);
    this._saveQueue = next.catch(() => {});
    return next;
  }

  async resetTask(taskId) {
    const stateFile = this.config.paths.stateFile;
    const dir = path.dirname(stateFile);
    await fs.mkdir(dir, { recursive: true });

    const token = `${Date.now()}:${crypto.randomUUID()}`;
    const markerPath = `${stateFile}.reset.${crypto.randomUUID()}.json`;
    const markerTmp = `${markerPath}.tmp`;
    await fs.writeFile(markerTmp, JSON.stringify({ taskId, token }), 'utf8');
    await fs.rename(markerTmp, markerPath);

    const updateOp = async () => {
      await this._loadStateFileOnly();
      delete this.state.roundsByTask[taskId];
      delete this.state.notifiedRoundCapByTask[taskId];
      this._loggedSkips.delete(taskId);
      this.state.resetAtByTask[taskId] = token;
      this._knownResetAtByTask[taskId] = token;
      await this._writeStateAtomic();
    };

    const next = this._saveQueue.then(updateOp, updateOp);
    this._saveQueue = next.catch(() => {});
    return next;
  }

  _logSkipOnce(taskId, revision, reason) {
    const sig = `${revision ?? 'x'}:${reason}`;
    if (!this.dryRun && this._loggedSkips.get(taskId) === sig) {
      return;
    }
    this._loggedSkips.set(taskId, sig);
    const prefix = this.dryRun ? '[dispatcher][dry-run]' : '[dispatcher]';
    this.logger.log(`${prefix} Skipping ${taskId}: ${reason}`);
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

  async _listAllPendingTasks(wing, maxPages = 20) {
    const all = [];
    let cursor = undefined;
    for (let pageIdx = 0; pageIdx < maxPages; pageIdx++) {
      const page = await this.client.listTasks({ state: 'pending', wing, limit: 50, cursor });
      const rows = page.tasks ?? [];
      all.push(...rows);
      if (!page.next_cursor || page.next_cursor === cursor) break;
      cursor = page.next_cursor;
    }
    return all;
  }

  async _readAllUnreadInbox(recipient, maxPages = 20) {
    const all = [];
    let cursor = undefined;
    for (let pageIdx = 0; pageIdx < maxPages; pageIdx++) {
      const page = await this.client.readInbox({
        recipient,
        unacknowledgedOnly: true,
        limit: 50,
        cursor,
      });
      const rows = page.messages ?? [];
      all.push(...rows);
      if (!page.next_cursor || page.next_cursor === cursor) break;
      cursor = page.next_cursor;
    }
    return all;
  }

  async _listResultEventIds(taskId, maxPages = 10) {
    const ids = new Set();
    if (typeof this.client.listEvents !== 'function') {
      return ids;
    }
    let cursor = undefined;
    for (let pageIdx = 0; pageIdx < maxPages; pageIdx++) {
      const page = await this.client.listEvents({ taskId, limit: 100, cursor });
      const events = page?.events ?? [];
      for (const ev of events) {
        if (ev.event_type === 'result_created' && ev.entity_id) {
          ids.add(ev.entity_id);
        }
      }
      if (!page?.next_cursor || page.next_cursor === cursor) break;
      cursor = page.next_cursor;
    }
    return ids;
  }

  /**
   * Perform a single poll cycle across pending tasks and enabled harness inboxes.
   * Returns a summary of dispatches launched or planned (in dry-run mode).
   */
  pollOnce() {
    if (this._stopRequested) {
      return Promise.resolve([]);
    }
    const run = this._runPollOnce().finally(() => {
      if (this._activePollPromise === run) {
        this._activePollPromise = null;
      }
    });
    this._activePollPromise = run;
    return run;
  }

  async _runPollOnce() {
    const dispatched = [];
    const hadExternalReset = await this._reconcileDiskResets();
    if (hadExternalReset && !this.dryRun) {
      await this.saveState();
    }

    if (this.config.polling.watchPendingTasks && !this._stopRequested) {
      const wings = this.config.polling.wings.length > 0 ? this.config.polling.wings : [undefined];
      for (const wing of wings) {
        if (this._stopRequested) break;
        const summaries = await this._listAllPendingTasks(wing);
        for (const summary of summaries) {
          if (this._stopRequested || this.activeRuns.size >= this.config.limits.maxConcurrent) break;
          if (this.activeRuns.has(summary.task_id)) continue;

          const task = await this._getFullTask(summary.task_id, summary.revision);
          if (this._stopRequested) break;

          const contract = parseDispatchContract(task.description);
          const depsCompleted = await this._areDependenciesCompleted(task);
          if (this._stopRequested) break;

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
            if (decision.capReached && !this.state.notifiedRoundCapByTask[task.task_id]) {
              this.logger.warn(`[dispatcher] Skipping ${task.task_id}: ${decision.reason}`);
              this.state.notifiedRoundCapByTask[task.task_id] = new Date().toISOString();
              await this.saveState();
              await this._notify(
                `[AgentPalace Dispatcher] Task \`${task.task_id}\` reached max rounds (${decision.reason}). Human review needed.`,
              );
            } else {
              this._logSkipOnce(task.task_id, task.revision, decision.reason);
            }
            continue;
          }

          if (!this._canRunHarness(decision.harnessName)) {
            continue;
          }

          const launched = this._launch({
            task,
            contract: decision.effectiveContract,
            harnessName: decision.harnessName,
            repoPath: decision.repoPath,
            branchPrefix: decision.branchPrefix,
            trigger: 'pending',
            messageIds: [],
          });
          if (launched) dispatched.push(launched);
        }
      }
    }

    if (this.config.polling.watchInbox && !this._stopRequested) {
      const enabledHarnesses = Object.values(this.config.harnesses).filter((h) => h.enabled);
      for (const harness of enabledHarnesses) {
        if (this._stopRequested || !this._canRunHarness(harness.name)) continue;

        const inboxMessages = await this._readAllUnreadInbox(harness.name);
        if (this._stopRequested) break;

        // Group unread, unseen messages by task_id.
        const byTask = new Map();
        for (const msg of inboxMessages) {
          if (this.state.seenMessageIds[msg.message_id]) continue;
          const list = byTask.get(msg.task_id) ?? [];
          list.push(msg);
          byTask.set(msg.task_id, list);
        }

        for (const [taskId, messages] of byTask.entries()) {
          if (this._stopRequested || !this._canRunHarness(harness.name)) break;
          if (this.activeRuns.has(taskId)) continue;

          let task;
          try {
            task = await this.client.getTask(taskId);
          } catch {
            continue;
          }
          if (this._stopRequested) break;

          const contract = parseDispatchContract(task.description);
          const roundsUsed = this.state.roundsByTask[taskId] ?? 0;

          const decision = evaluateInboxTask({
            task,
            contract,
            config: this.config,
            activeRuns: this.activeRuns,
            roundsUsed,
            messages,
            harness,
          });

          if (!decision.eligible) {
            if (decision.capReached && !this.state.notifiedRoundCapByTask[taskId]) {
              this.logger.warn(
                `[dispatcher] Ping-pong cap reached for ${taskId} (${roundsUsed}/${decision.maxRounds}); leaving unread messages for human review.`,
              );
              this.state.notifiedRoundCapByTask[taskId] = new Date().toISOString();
              await this.saveState();
              await this._notify(
                `[AgentPalace Dispatcher] Task \`${taskId}\` reached max rounds (${decision.maxRounds}) with unread messages for \`${harness.name}\`. Human input needed.`,
              );
            } else {
              this._logSkipOnce(taskId, task.revision, `inbox(${harness.name}): ${decision.reason}`);
            }
            continue;
          }

          const messageIds = decision.messages.map((m) => m.message_id);

          const launched = this._launch({
            task,
            contract: decision.effectiveContract,
            harnessName: harness.name,
            repoPath: decision.repoPath,
            branchPrefix: decision.branchPrefix,
            trigger: 'inbox',
            messageIds,
          });
          if (launched) dispatched.push(launched);
        }
      }
    }

    return dispatched;
  }

  _launch({ task, contract, harnessName, repoPath, branchPrefix, trigger, messageIds }) {
    if (this._stopRequested) {
      return null;
    }

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

    const promise = this._executeRun({ task, contract, harnessName, repoPath, branchPrefix, trigger, messageIds })
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

  async _executeRun({ task, contract, harnessName, repoPath, branchPrefix, trigger, messageIds }) {
    const harness = this.config.harnesses[harnessName];
    let claimedTask = task;
    let dispatcherClaimed = false;
    let leaseTimer = null;

    try {
      // Snapshot pre-run result events BEFORE mutating rounds, worktrees, or claiming a lease,
      // so a transient snapshot failure skips this poll cleanly without counting old results as new.
      let beforeResultIds = new Set();
      let baselineSnapshotOk = false;
      const shouldDispatcherClaim = this.config.limits.claimMode === 'dispatcher' && task.state === 'pending';
      if (shouldDispatcherClaim && typeof this.client.listEvents === 'function') {
        try {
          beforeResultIds = await this._listResultEventIds(task.task_id);
          baselineSnapshotOk = true;
        } catch (err) {
          this.logger.warn(
            `[dispatcher] Could not snapshot pre-run result events for ${task.task_id} (${err.message}); skipping claim this poll.`,
          );
          return;
        }
      }

      // Increment round count up front so repeated worktree/setup errors also hit maxRounds.
      this.state.roundsByTask[task.task_id] = (this.state.roundsByTask[task.task_id] ?? 0) + 1;
      await this.saveState();

      // Prepare working directory BEFORE claiming so worktree failures never leak a lease.
      let cwd = repoPath || process.cwd();
      let worktreePath = null;
      if (contract.mode === 'worktree_branch' || contract.mode === 'draft_pr') {
        const effectivePrefix = branchPrefix || 'agent/';
        const expectedBranch = contract.branch || `${effectivePrefix}${sanitizeSlug(task.task_id)}`;
        const allowReuseExistingBranch = this.state.managedBranches[task.task_id] === expectedBranch;
        const wt = await this.worktreeManager.ensureWorktree({
          repoPath,
          worktreeRoot: this.config.paths.worktreeRoot,
          taskId: task.task_id,
          branch: contract.branch,
          baseRef: contract.baseRef || 'HEAD',
          branchPrefix: effectivePrefix,
          allowReuseExistingBranch,
        });
        cwd = wt.worktreePath;
        worktreePath = wt.worktreePath;
        if (this.state.managedBranches[task.task_id] !== wt.branchName) {
          this.state.managedBranches[task.task_id] = wt.branchName;
          await this.saveState();
        }
      }

      // Optional dispatcher-owned claim + lease renewal heartbeat.
      if (shouldDispatcherClaim) {
        claimedTask = await this.client.claimTask(task.task_id, {
          expectedRevision: task.revision,
          leaseSeconds: this.config.limits.leaseSeconds,
          worker: harnessName,
        });
        dispatcherClaimed = true;
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
      const rawTimeout = contract.timeoutMs ?? harness.timeoutMs ?? this.config.limits.defaultTimeoutMs;
      const timeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(10000, rawTimeout));

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
        onSpawn: (child) => {
          this._activeChildren.add(child);
          child.once?.('close', () => this._activeChildren.delete(child));
        },
      });

      // Only suppress re-wake for triggering inbox messages when the harness exited cleanly.
      // If it crashed or timed out, keep them eligible for retry (bounded by maxRounds).
      if (runResult.exitCode === 0 && !runResult.timedOut && messageIds.length > 0) {
        for (const id of messageIds) {
          this.state.seenMessageIds[id] = new Date().toISOString();
        }
        await this.saveState();
      }

      // Authoritative post-exit verification (per docs/Agent-Task-Handoffs.md):
      // Process exit 0 alone is NOT proof of task completion.
      let afterTask = null;
      try {
        afterTask = await this.client.getTask(task.task_id);
        this.taskCache.set(task.task_id, { revision: afterTask.revision, task: afterTask });
      } catch (err) {
        this.logger.warn(`[dispatcher] Post-exit task fetch failed for ${task.task_id}: ${err.message}`);
      }

      // Reconcile dispatcher-owned leases on both failure and clean exit.
      if (dispatcherClaimed && afterTask?.state === 'running') {
        if (runResult.exitCode !== 0 || runResult.timedOut) {
          try {
            afterTask = await this.client.transitionTask(afterTask.task_id, {
              expectedRevision: afterTask.revision,
              state: 'pending',
              actor: harnessName,
              details: {
                reason: runResult.timedOut ? 'dispatcher_timeout' : 'harness_nonzero_exit',
                exitCode: runResult.exitCode,
              },
            });
          } catch (err) {
            this.logger.warn(`[dispatcher] Failed to release lease for ${task.task_id}: ${err.message}`);
          }
        } else {
          let newResultIds = [];
          let verifyOk = false;
          if (baselineSnapshotOk) {
            try {
              const afterResultIds = await this._listResultEventIds(task.task_id);
              newResultIds = [...afterResultIds].filter((id) => !beforeResultIds.has(id));
              verifyOk = true;
            } catch (err) {
              this.logger.warn(`[dispatcher] Result event check failed for ${task.task_id}: ${err.message}`);
            }
          }

          const delivered = baselineSnapshotOk && verifyOk && newResultIds.length > 0;
          const targetState = delivered
            ? (this.config.limits.dispatcherSuccessState ?? 'input_required')
            : 'pending';
          const reason = delivered
            ? 'dispatcher_reconciled_result'
            : !baselineSnapshotOk
              ? 'result_baseline_unavailable'
              : !verifyOk
                ? 'result_verification_failed'
                : 'harness_exited_without_result';

          if (!delivered) {
            this.logger.warn(
              `[dispatcher] Yielding ${task.task_id} back to pending after clean exit (${reason}).`,
            );
          }

          try {
            afterTask = await this.client.transitionTask(afterTask.task_id, {
              expectedRevision: afterTask.revision,
              state: targetState,
              actor: harnessName,
              details: { reason, resultIds: newResultIds },
            });
            this.taskCache.set(task.task_id, { revision: afterTask.revision, task: afterTask });
          } catch (err) {
            this.logger.warn(`[dispatcher] Failed to reconcile task ${task.task_id} to ${targetState}: ${err.message}`);
          }
        }
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
    if (this._activePollPromise) {
      await this._activePollPromise.catch(() => {});
    }
    await this.waitForInflight();
    await this._saveQueue.catch(() => {});
  }

  async forceStop() {
    this._stopRequested = true;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    await Promise.allSettled(
      [...this._activeChildren].map((child) => killProcessTree(child, { graceMs: 1500 })),
    );
    await this._saveQueue.catch(() => {});
  }
}

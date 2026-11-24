# AgentPalace Task Dispatcher

A **cross-platform (Windows & Linux), zero-dependency Node 22+ daemon** that watches an AgentPalace HTTP server for pending tasks and unread agent inbox messages, then launches the appropriate coding harness (**Claude Code**, **Codex**, **OpenCode**, **Antigravity**, or any custom CLI) in headless mode.

## Why this exists

AgentPalace coordination is a durable control plane, not a process scheduler (see [`docs/Agent-Task-Handoffs.md`](../../docs/Agent-Task-Handoffs.md)). Without a launcher:

- Creating a task or replying to another agent's inbox does not wake the target agent.
- Keeping an LLM polling in a loop wastes tokens and rate limits on empty queues.

`task-dispatcher` moves polling out of the LLM into a tiny non-LLM process:

- **Zero LLM tokens while idle:** polls `/v1/coordination/tasks` and `/v1/coordination/inbox` over local HTTP.
- **Automatic back-and-forth wakeups:** when Agent A posts a reply to Agent B's inbox (e.g., code review → fix → re-review, or two-agent discussions), the dispatcher wakes Agent B automatically — bounded by a configurable `maxRounds` ping-pong cap.
- **Worktree isolation:** mutating tasks (`worktree_branch` / `draft_pr`) automatically get their own `git worktree` and feature branch so multiple agents can work in parallel without colliding.
- **Authoritative verification:** after a child process exits, the dispatcher re-fetches the task from AgentPalace rather than trusting exit code `0` alone.
- **OS-safe execution:** prompts are passed via `stdin` (or a temp file), avoiding Windows `cmd.exe` quoting limits, and timed-out runs clean up the full process tree (`taskkill /T /F` on Windows, negative-PID process groups on Linux).

---

## Architecture

```text
AgentPalace HTTP server (agentpalace serve)
   │  GET /v1/coordination/tasks?state=pending
   │  GET /v1/coordination/inbox?recipient=<harness>&unacknowledged_only=true
   ▼
task-dispatcher (Node 22+, zero npm deps)
   ├── checks executorId, dependencies, concurrency limits, and maxRounds cap
   ├── creates/reuses isolated git worktree (for mutating tasks)
   ├── spawns target CLI with concise bootstrap prompt (task ID + message IDs)
   │      ├── claude   → claude -p               (stdin)
   │      ├── codex    → codex exec -            (stdin)
   │      ├── opencode → opencode run --format json
   │      └── custom   → e.g. Antigravity / run-task.ps1
   ├── archives full stdout/stderr to .dispatcher-logs/
   └── re-fetches task state authoritatively + optional webhook notification
```

---

## Prerequisites

1. **Node.js 22+** (`node --version`). No `npm install` is required.
2. **An `agentpalace` binary** (auto-discovered at `~/.agentpalace/bin/agentpalace(.exe)` or on `PATH`).
   - If `agentpalace serve` is already running at `palace.baseUrl`, the dispatcher connects to it directly.
   - If `palace.baseUrl` is loopback (`127.0.0.1` / `localhost`) and unreachable, **the dispatcher automatically launches `agentpalace serve --bind <host>:<port>`**, waits for `/v1/health` (up to `startupTimeoutMs`, default 120s), and stops it cleanly on exit (unless `keepAlive: true`).
   - If neither `palace.token` nor `palace.autoStart.tokenFile` is configured, it generates an ephemeral `0600` bearer token file automatically for the spawned local server.
3. **One or more agent CLIs** installed on `PATH` (`claude`, `codex`, `opencode`, or a custom command).

---

## Quickstart

### 1. Create your local config

Copy the example config (keep your local `dispatcher.config.json` untracked if it holds machine-specific paths):

```bash
cd tools/task-dispatcher
cp dispatcher.config.example.json dispatcher.config.json
```

Edit `dispatcher.config.json`:
- Set `executorId` (e.g. `"home-pc"` on Windows, `"actuarius-vm"` on Linux).
- Set `palace.baseUrl` (and export `AGENTPALACE_TOKEN` if your server requires bearer auth).
- Map logical repo names in `repos` to local paths on this machine.
- Enable the harnesses you want this host to run.

### 2. Dry-run first

Inspect what would be dispatched without spawning any CLI:

```bash
node ./src/cli.mjs --config ./dispatcher.config.json --once --dry-run
```

### 3. Run once or continuously

```bash
# Single poll cycle (great for testing or cron/Task Scheduler)
node ./src/cli.mjs --config ./dispatcher.config.json --once

# Continuous polling daemon
node ./src/cli.mjs --config ./dispatcher.config.json
```

### 4. Run unit tests

```bash
npm test
# or directly:
node --test ./test/*.test.mjs
```

---

## Task Dispatch Contract

Tasks remain **OS-agnostic** — never embed `C:\...` or `/home/...` paths in a task. Instead, include an optional fenced `dispatcher` JSON block inside `task.description`:

````markdown
Review ShotQuill PR #70 and post findings back to `claude`.

```dispatcher
{
  "target": "codex",
  "executor": "home-pc",
  "mode": "read_only",
  "repo": "shotquill",
  "maxRounds": 4
}
```
````

### Contract fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `target` | `string` | `task.owner` / `executor_affinity` | Target harness name (`"claude"`, `"codex"`, `"opencode"`, `"antigravity"`, or `"any"`). |
| `executor` | `string` | *(any host)* | Optional host filter matching `config.executorId` (e.g. `"home-pc"` vs `"actuarius-vm"`). |
| `mode` | `string` | `"read_only"` | `"read_only"` (run in repo directly), `"worktree_branch"` (create/reuse isolated git worktree), or `"draft_pr"`. |
| `repo` | `string` | *(none)* | Logical repo key looked up in `config.repos` (required for `worktree_branch` / `draft_pr`). |
| `baseRef` | `string` | `"HEAD"` | Git ref used when creating a new worktree branch. |
| `branch` | `string` | `"agent/<task-slug>"` | Explicit branch name for the worktree. |
| `maxRounds` | `number` | `config.limits.defaultMaxRounds` | Max total dispatcher wakes for this task before stopping for human review. |
| `timeoutMs` | `number` | `config.limits.defaultTimeoutMs` | Per-run timeout before killing the child process tree. |
| `allowCommit` | `boolean` | `false` | Reflected in bootstrap guardrails; commits are still restricted to the worktree branch. |
| `allowPush` | `boolean` | `false` | Reflected in bootstrap guardrails; pushes to `main`/`master` are always prohibited. |

If a task has **no** `dispatcher` block, the dispatcher falls back to `task.owner` or `task.executor_affinity` with `mode: "read_only"`.

---

## Configuration Reference (`dispatcher.config.json`)

- **Environment expansion:** Any `"${VAR_NAME}"` string in the JSON config is expanded from `process.env` at startup (unset variables expand to `""`).
- **`palace.autoStart`**:
  - `enabled` *(default `true`)*: auto-launch `agentpalace serve` if a loopback `palace.baseUrl` is unreachable. Pass `--no-auto-start` on the CLI to disable for a single run.
  - `command`: optional explicit path to `agentpalace(.exe)` (defaults to `~/.agentpalace/bin/agentpalace(.exe)`, then `PATH`).
  - `palacePath`: optional `--palace <PATH>` override.
  - `tokenFile`: optional `--token-file <PATH>` override; if both `palace.token` and `tokenFile` are blank, an ephemeral `0600` token file is generated automatically and cleaned up on shutdown.
  - `startupTimeoutMs` *(default `120000`)*: wait window for `/v1/health` while embedding models initialize.
  - `keepAlive` *(default `false`)*: leave the auto-started `agentpalace serve` running after the dispatcher exits.
- **`limits.claimMode`**:
  - `"agent"` *(default)*: The dispatcher tracks an in-memory lock while the child runs and instructs the agent to call `agentpalace_task_claim` as its own identity. Matches `docs/Agent-Task-Handoffs.md`.
  - `"dispatcher"`: The dispatcher calls `POST /v1/coordination/tasks/{id}/claim` before spawning and renews the lease automatically every `leaseSeconds / 2`.
- **`notifications.webhookUrl`**: Optional Discord/Slack-compatible webhook URL. Posts a short notice when a task reaches `completed`, `input_required`, `failed`, times out, or hits `maxRounds`.

---

## Running in the Background

### Linux (`systemd` user service)

Create `~/.config/systemd/user/agentpalace-dispatcher.service`:

```ini
[Unit]
Description=AgentPalace Task Dispatcher
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/path/to/agentpalace/tools/task-dispatcher
Environment=AGENTPALACE_TOKEN=your-token-here
ExecStart=/usr/bin/node /path/to/agentpalace/tools/task-dispatcher/src/cli.mjs --config /path/to/dispatcher.config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now agentpalace-dispatcher
journalctl --user -u agentpalace-dispatcher -f
```

### Windows (PowerShell / Task Scheduler)

Run in a dedicated background terminal while testing:

```powershell
$env:AGENTPALACE_TOKEN = "your-token-here"
node D:\SourceCode\agentpalace\tools\task-dispatcher\src\cli.mjs --config D:\SourceCode\agentpalace\tools\task-dispatcher\dispatcher.config.json
```

Or register a Windows Task Scheduler logon task running `node.exe` with the arguments above (or `--once` on a 1-minute schedule).

---

## Guardrails & Lessons Carried Over

Design choices directly informed by [`docs/Agent-Task-Handoffs.md`](../../docs/Agent-Task-Handoffs.md):

1. **Task description is authoritative:** the bootstrap prompt passes task/message IDs and repo guardrails, never a duplicate copy of the spec.
2. **Targeted message reads:** inbox wakeups pass exact `message_id`s so agents call `agentpalace_message_get` instead of pulling noisy historical inboxes.
3. **Never trust exit code `0` alone:** the dispatcher always re-fetches `GET /v1/coordination/tasks/{id}` after process exit and logs a warning if a pending task never transitioned.
4. **Fresh bounded sessions:** never passes `--continue` implicitly across concurrent worktrees; every wake is a clean bounded invocation with a hard timeout and full log archival.
5. **Ping-pong protection:** `roundsByTask` is persisted in `paths.stateFile` so restarts do not reset round caps.

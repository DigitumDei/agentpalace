# AgentPalace Task Dispatcher

A **cross-platform (Windows & Linux), zero-dependency Node 22+ daemon** that watches an AgentPalace HTTP server for pending tasks and unread agent inbox messages, then launches the appropriate coding harness (**Claude Code**, **Codex**, **OpenCode**, or any custom CLI) in headless mode.

## Why this exists

AgentPalace coordination is a durable control plane, not a process scheduler (see [`docs/Agent-Task-Handoffs.md`](../../docs/Agent-Task-Handoffs.md)). Without a launcher:

- Creating a task or replying to another agent's inbox does not wake the target agent.
- Keeping an LLM polling in a loop wastes tokens and rate limits on empty queues.

`task-dispatcher` moves polling out of the LLM into a tiny non-LLM process:

- **Zero LLM tokens while idle:** polls `/v1/coordination/tasks` and `/v1/coordination/inbox` over local HTTP.
- **Automatic back-and-forth wakeups:** when Agent A posts a reply to Agent B's inbox (e.g., code review → fix → re-review, or two-agent discussions), the dispatcher wakes Agent B automatically — bounded by a configurable `maxRounds` / `maxRoundsCap` ping-pong cap.
- **Local trust ceiling:** dispatcher-enforced limits (`policy`, `limits`, per-repo `allowedModes` / `branchPrefix`, `maxRoundsCap`, `maxTimeoutMs`) cap what a task can trigger; see [Enforced vs. advisory guardrails](#enforced-vs-advisory-guardrails) below for prompt-level rules on unsandboxed CLIs.
- **Worktree isolation:** mutating tasks (`worktree_branch` / `draft_pr`) automatically get their own `git worktree` and prefixed branch (`agent/<slug>`) so multiple agents can work in parallel without colliding or touching `main`.
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
   ├── checks policy (wings, allowedCreators/Senders, allowedModes, caps)
   ├── creates/reuses isolated git worktree on an agent/-prefixed branch
   ├── spawns target CLI with concise bootstrap prompt (task ID + message IDs)
   │      ├── claude   → claude -p               (stdin)
   │      ├── codex    → codex exec -            (stdin)
   │      ├── opencode → opencode run --format json
   │      └── custom   → arbitrary runner / wrapper script
   ├── archives full stdout/stderr to .dispatcher-logs/
   └── re-fetches task state authoritatively + optional webhook notification
```

---

## Prerequisites

1. **Node.js 22+** (`node --version`). No `npm install` is required.
2. **An AgentPalace HTTP server** (or `agentpalace` binary on `PATH` / `~/.agentpalace/bin/agentpalace(.exe)` if using opt-in `--auto-start`):
   ```bash
   agentpalace serve --bind 127.0.0.1:8775
   ```
   > **Warning — do not enable `autoStart` on an SSH/federation tunnel port (e.g. `127.0.0.1:8765`):** `palace.autoStart.enabled` defaults to `false` so a temporarily closed tunnel will never cause the dispatcher to spin up a local shadow palace on the tunnel's port. Only set `autoStart.enabled: true` (or pass `--auto-start`) on a dedicated local port such as `127.0.0.1:8775`.
3. **One or more agent CLIs** installed on `PATH` (`claude`, `codex`, `opencode`, or a custom command).
   - **Headless Claude (`claude -p`):** non-interactive runs require explicit tool permissions in `harnesses.claude.extraArgs`. The example config starts safely with read-only git/file inspection plus AgentPalace MCP tools (`["--permission-mode", "dontAsk", "--allowedTools", "Read,Glob,Grep,Bash(git status*),Bash(git diff*),Bash(git log*),mcp__agentpalace__*"]`); widen `--allowedTools` only for trusted mutating workflows, otherwise Claude will lack permission to edit files or run tests.

---

## Quickstart

### 1. Create your local config

Copy the example config (keep your local `dispatcher.config.json` untracked if it holds machine-specific paths):

```bash
cd tools/task-dispatcher
cp dispatcher.config.example.json dispatcher.config.json
```

Edit `dispatcher.config.json`:
- Set `executorId` (e.g. `"home-pc"` on Windows, `"build-vm"` on Linux).
- Set `palace.baseUrl` (and export `AGENTPALACE_TOKEN` if your server requires bearer auth).
- Configure `policy` (`allowedCreators`, `allowedSenders`, `allowedModes`, `allowCommit`, `allowPush`, `branchPrefix`) and map logical repo names in `repos`.
- Enable the harnesses you want this host to run.

### 2. Dry-run first

Inspect what would be dispatched (and why ineligible tasks are skipped) without spawning any CLI:

```bash
node ./src/cli.mjs --config ./dispatcher.config.json --once --dry-run
```

### 3. Run once, continuously, or reset a capped task

```bash
# Single poll cycle (great for testing or cron/Task Scheduler)
node ./src/cli.mjs --config ./dispatcher.config.json --once

# Same, opting into automatic local `agentpalace serve` startup on a dedicated port
node ./src/cli.mjs --config ./dispatcher.config.json --once --auto-start

# Continuous polling daemon
node ./src/cli.mjs --config ./dispatcher.config.json

# Resume a task that hit maxRounds after human review (works offline or while daemon is running)
node ./src/cli.mjs --config ./dispatcher.config.json --reset-task task_abc123
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
Review example-app PR #42 and post findings back to `claude`.

```dispatcher
{
  "target": "codex",
  "executor": "home-pc",
  "mode": "read_only",
  "repo": "example-app",
  "maxRounds": 4
}
```
````

### Contract fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `target` | `string` | `task.owner` / `executor_affinity` | Target harness name (`"claude"`, `"codex"`, `"opencode"`, or `"any"`). |
| `executor` | `string` | *(any host)* | Optional host filter matching `config.executorId`. |
| `mode` | `string` | `"read_only"` | `"read_only"` (run in repo directly), `"worktree_branch"` (create/reuse isolated git worktree), or `"draft_pr"`. Capped by local `policy.allowedModes` / per-repo `allowedModes`. |
| `repo` | `string` | *(none)* | Logical repo key looked up in `config.repos` (required for `worktree_branch` / `draft_pr` on both pending and inbox runs). |
| `baseRef` | `string` | `"HEAD"` | Git ref used when creating a new worktree branch (validated against option injection and resolved via `git rev-parse --verify`). |
| `branch` | `string` | `"<branchPrefix><task-slug>"` | Explicit branch name for the worktree; must start with `branchPrefix` (default `"agent/"`) and cannot reuse unmanaged pre-existing branches. |
| `maxRounds` | `number` | `config.limits.defaultMaxRounds` | Max total dispatcher wakes before stopping for human review; clamped to `limits.maxRoundsCap`. |
| `timeoutMs` | `number` | `config.limits.defaultTimeoutMs` | Per-run timeout before killing the child process tree; clamped to `min(limits.maxTimeoutMs, 2147483647)`. |
| `allowCommit` | `boolean` | `false` | Effective only when local `policy.allowCommit` / per-repo `allowCommit` is also `true`; commits are still restricted to the worktree branch. |
| `allowPush` | `boolean` | `false` | Effective only when local `policy.allowPush` / per-repo `allowPush` is also `true`; pushes to `main`/`master` are always prohibited. |

If a task has **no** `dispatcher` block, the dispatcher falls back to `task.owner` or `task.executor_affinity` with `mode: "read_only"`.

---

## Configuration Reference (`dispatcher.config.json`)

- **Environment expansion:** Any `"${VAR_NAME}"` string in the JSON config is expanded from `process.env` at startup (unset variables expand to `""`).
- **`palace.tokenIdentity` & `harnesses.<name>.actorAliases`**:
  - When tasks are claimed/yielded via HTTP REST, `agentpalace-server` records workers as `<tokenName>:<harness>` (e.g. `home-pc:codex`) whenever the claimed worker differs from the token's own identity.
  - Set `palace.tokenIdentity` to your token's name (or `"*"` on a private local palace), or list explicit `actorAliases` on each harness, so yielded pending tasks re-dispatch cleanly.
- **`palace.autoStart`**:
  - `enabled` *(default `false`)*: auto-launch `agentpalace serve` if a loopback `palace.baseUrl` is unreachable. Never enable on a port shared with an SSH/federation tunnel.
  - `command`: optional explicit path to `agentpalace(.exe)` (defaults to `~/.agentpalace/bin/agentpalace(.exe)`, then `PATH`).
  - `palacePath`: optional `--palace <PATH>` override.
  - `tokenFile`: optional `--token-file <PATH>` override; if both `palace.token` and `tokenFile` are blank (and `keepAlive` is `false`), an ephemeral `0600` token file is generated automatically and cleaned up on shutdown.
  - `startupTimeoutMs` *(default `120000`, max `2147483647`)*: wait window for `/v1/health` while embedding models initialize.
  - `keepAlive` *(default `false`)*: leave the auto-started `agentpalace serve` running after the dispatcher exits (requires a persistent `palace.token` / `tokenFile`).
- **`policy` & per-repo overrides (`repos.<name>`)**:
  - `allowedCreators` / `allowedSenders`: optional allowlists of `task.created_by` and inbox `msg.sender` actors (recommended whenever connecting to a multi-user hub).
  - `allowedModes`, `allowCommit`, `allowPush`, `branchPrefix` *(default `"agent/"`)*: local upper bounds that task descriptions cannot exceed. Each entry in `repos` can be either a path string or `{ path, allowedModes, allowCommit, allowPush, branchPrefix }`.
- **`limits.claimMode`**:
  - `"agent"` *(default)*: The dispatcher tracks an in-memory lock while the child runs and instructs the agent to call `agentpalace_task_claim` and transition state as its own identity. Matches `docs/Agent-Task-Handoffs.md`.
  - `"dispatcher"`: The dispatcher calls `POST /v1/coordination/tasks/{id}/claim` before spawning, renews the lease every `leaseSeconds / 2`, and reconciles the task after exit — transitioning to `limits.dispatcherSuccessState` (`"input_required"` by default, or `"completed"`) when a new `result_created` event was published, or yielding back to `"pending"` if the run crashed, timed out, or exited without publishing a result.
- **`--reset-task <id>` behavior:** works both offline and against a running dispatcher daemon. It clears `roundsByTask.<id>` and `notifiedRoundCapByTask.<id>` in `paths.stateFile` and writes a reset marker so a running daemon reconciles the reset into memory before its next poll or state save without overwriting it.
- **`notifications.webhookUrl`**: Optional Discord/Slack-compatible webhook URL. Posts a notice when a task reaches `completed`, `input_required`, `failed`, times out, or hits `maxRounds` (once per capped task).

### Enforced vs. advisory guardrails

- **Mechanically enforced by the dispatcher:** `polling.wings`, `policy.allowedCreators`, `policy.allowedSenders`, `repos` path mapping, `allowedModes` gating, isolated `git worktree` creation on `branchPrefix`-enforced branches (refusing unmanaged pre-existing branches), `baseRef` option-injection checks, `limits.maxRoundsCap`, and `limits.maxTimeoutMs` (process-tree termination).
- **Advisory for unsandboxed CLIs:** `read_only`, `allowCommit: false`, and `allowPush: false` are passed as absolute local-policy rules in the bootstrap prompt (never overridable by task text), and are only mechanically enforced to the extent the underlying harness sandbox or `--allowedTools` restricts tool use. By default, `dispatcher.config.example.json` restricts Claude's `--allowedTools` to read-only file/git inspection and AgentPalace MCP tools.

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
node C:\path\to\agentpalace\tools\task-dispatcher\src\cli.mjs --config C:\path\to\agentpalace\tools\task-dispatcher\dispatcher.config.json
```

Or register a Windows Task Scheduler logon task running `node.exe` with the arguments above (or `--once` on a 1-minute schedule).

---

## Guardrails & Lessons Carried Over

Design choices directly informed by [`docs/Agent-Task-Handoffs.md`](../../docs/Agent-Task-Handoffs.md):

1. **Task description is authoritative:** the bootstrap prompt passes task/message IDs and repo guardrails, never a duplicate copy of the spec.
2. **Targeted message reads:** inbox wakeups pass exact `message_id`s so agents call `agentpalace_message_get` instead of pulling noisy historical inboxes.
3. **Never trust exit code `0` alone:** the dispatcher always re-fetches `GET /v1/coordination/tasks/{id}` (and `result_created` events in `dispatcher` claim mode) after process exit.
4. **Fresh bounded sessions:** never passes `--continue` implicitly across concurrent worktrees; every wake is a clean bounded invocation with a hard timeout and full log archival.
5. **Fail-closed persisted state:** `paths.stateFile` is written atomically (`tmp` + `rename`, serialized queue) and refuses to silently reset round caps on corrupt JSON.

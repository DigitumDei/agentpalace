# AgentPalace Tools

Auxiliary standalone tools that complement the core Rust `agentpalace` binary without adding runtime dependencies to the workspace crates.

| Tool | Description | Runtime |
| --- | --- | --- |
| [`task-dispatcher`](./task-dispatcher/README.md) | Cross-platform (Windows & Linux) zero-token watcher that polls AgentPalace coordination tasks & inboxes and launches Claude, Codex, OpenCode, or Antigravity headless in isolated git worktrees. | Node 22+ (zero dependencies) |

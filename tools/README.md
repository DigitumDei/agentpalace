# AgentPalace Tools

Auxiliary standalone tools that complement the core Rust `agentpalace` binary without adding runtime dependencies to the workspace crates.

| Tool | Description | Runtime |
| --- | --- | --- |
| [`task-dispatcher`](./task-dispatcher/README.md) | Cross-platform (Windows & Linux) zero-token watcher that polls AgentPalace coordination tasks & inboxes and launches Claude, Codex, OpenCode, or Antigravity headless in isolated git worktrees. | Node 22+ (zero dependencies) |
| [`issue-agent`](./issue-agent/README.md) | Hands one GitHub issue to a Claude Managed Agent that implements it on a branch in a cloud sandbox, then opens a draft pull request from the agent's description. Contributor tooling; calls the Claude API. | Node 22+ (`@anthropic-ai/sdk`), `gh`, `ant` |

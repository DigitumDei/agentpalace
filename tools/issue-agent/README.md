# issue-agent

Hands one GitHub issue to a [Claude Managed Agent](https://platform.claude.com/docs/en/managed-agents/overview), which implements it on a branch in a cloud sandbox. When the session ends, this tool opens a draft pull request from the description the agent wrote.

This is contributor tooling. It is not part of the `agentpalace` binary and adds nothing to the workspace crates. Running it sends the issue text to Anthropic and gives the agent a clone of this repository in an Anthropic-hosted sandbox. It never touches a palace.

## What happens in a run

1. `src/run.mjs` reads the issue with `gh` and starts a session with the repository mounted at `/workspace/agentpalace`.
2. The agent reads `CLAUDE.md`, works on `agent/issue-<number>`, runs the check, clippy and per-package test commands, and pushes the branch.
3. A separate grader scores the result against the rubric in `src/lib.mjs` and sends the agent back to revise, up to three rounds.
4. The agent writes the pull request description to `/mnt/session/outputs/pr.md`. The runner downloads it to `out/issue-<number>/` and runs `gh pr create --draft` under your own `gh` login.

The agent is told to stop instead of guessing when an issue needs a maintainer decision. In that case `pr.md` starts with `BLOCKED:`, no branch is pushed and no pull request is opened.

## Files

| Path | Purpose |
| --- | --- |
| `agents/issue-to-pr.md` | Agent definition: model, tools and system prompt. |
| `environments/rust-dev.yaml` | Sandbox definition: deny-by-default networking with package managers and the Rust hosts allowed. |
| `claude-lock.json` | Written by `ant apply`. Holds the agent and environment IDs from your own Claude workspace. Gitignored: each contributor creates their own agent, so keep the file, because without it the next `ant apply` creates duplicates. |
| `src/run.mjs` | Starts one session and follows it to the end. |
| `src/lib.mjs` | Argument parsing, the rubric, the probe prompt and other pure helpers. |
| `test/lib.test.mjs` | Tests for `src/lib.mjs`. |

## One-time setup

Needs Node 22 or later, the [`gh`](https://cli.github.com/) CLI signed in to this repository, and the [`ant`](https://github.com/anthropics/anthropic-cli) CLI 1.30.0 or later. Run everything from `tools/issue-agent`.

1. Install the dependency:

   ```sh
   npm install
   ```

2. Sign in to the Claude API. The runner and `ant` both pick up this profile:

   ```sh
   ant auth login
   ```

3. Create the agent and the environment. The first command prints the plan and changes nothing; the second asks before it creates anything:

   ```sh
   ant apply --dry-run -v agents/issue-to-pr.md environments/rust-dev.yaml
   ant apply agents/issue-to-pr.md environments/rust-dev.yaml
   ```

   Name the two files as shown. `ant apply .` walks the directory and would also apply anything else that looks like a resource.

4. Create a fine-grained GitHub token limited to this repository with **Contents: Read and write**, and export it as `ISSUE_AGENT_GITHUB_TOKEN`. The token mounts the repository and lets the agent push its branch. It is injected by a proxy outside the sandbox, so code running in the sandbox cannot read it.

## Usage

Check the sandbox first. The probe reports which toolchain the container has, whether the token can push, and whether `cargo fetch` can reach its hosts:

```sh
npm run probe
```

Then hand over an issue:

```sh
npm run issue -- 109
```

| Option | Effect |
| --- | --- |
| `--budget-usd <n>` | Hard spend cap for the session. Default 10, or 2 for the probe. |
| `--no-pr` | Download the description but do not open the pull request. |
| `--probe` | Run the sandbox check instead of an issue. |

| Environment variable | Purpose |
| --- | --- |
| `ISSUE_AGENT_GITHUB_TOKEN` | Required. The repository token from setup step 4. |
| `ISSUE_AGENT_ID`, `ISSUE_AGENT_ENVIRONMENT_ID` | Optional. Override the IDs in `claude-lock.json`. |
| `ISSUE_AGENT_WORKSPACE` | Optional. Console workspace ID for the printed session link. Defaults to the workspace recorded in `claude-lock.json`. |

| Exit code | Meaning |
| --- | --- |
| 0 | Pull request opened, probe finished, or `--no-pr` run completed. |
| 1 | The session failed, hit its spend cap, or produced no usable result. |
| 2 | Bad arguments, missing setup, or the issue is not open. |
| 3 | The agent reported `BLOCKED:` and is waiting on a maintainer decision. |

The runner prints a Console link when the session starts. Sessions are kept until you delete them; the runner never archives or deletes one.

## Limits on the agent

- Both web tools are off, and the sandbox reaches only package registries and the hosts in `environments/rust-dev.yaml`.
- Tool calls run under the `auto` permission policy: the platform runs calls it judges safe and denies high-risk ones. A call it cannot judge pauses; the runner asks you at the terminal and denies it when no terminal is attached.
- The system prompt bars commits to `main` and changes under `.github/workflows/` and `release/`. `main` is also protected by the repository ruleset.
- The sandbox is Linux, so the agent cannot verify Windows or macOS behaviour.

Review the pull request as you would any other. A grader verdict of "satisfied" means the rubric was met, not that the change is right.

## Changing the agent

Edit `agents/issue-to-pr.md` or `environments/rust-dev.yaml` and run the two `ant apply` commands again. An agent edit creates a new version; running sessions keep the version they started with. Do not edit the agent in the Console, because the next `ant apply` then refuses to run.

The rubric is a starter. Tune the criteria in `src/lib.mjs` as real runs show what the grader rewards and what it misses.

## Test

```sh
npm test
```

The tests cover the pure helpers only. Nothing here exercises a live session.

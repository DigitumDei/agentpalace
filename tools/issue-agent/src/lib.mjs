// Pure helpers for the issue-to-PR runner. No network, no process access, so
// they can be tested without credentials.

export const AGENT_LOCK_KEY = './agents/issue-to-pr.md';
export const ENVIRONMENT_LOCK_KEY = './environments/rust-dev.yaml';
export const REPO_MOUNT_PATH = '/workspace/agentpalace';
export const DEFAULT_BUDGET_USD = 10;
export const PROBE_BUDGET_USD = 2;

export const USAGE = `Usage:
  node src/run.mjs <issue-number> [options]   implement one issue, then open a draft PR
  node src/run.mjs --probe [options]          check the sandbox toolchain and repository access

Options:
  --budget-usd <n>   hard spend cap for the session in US dollars (default ${DEFAULT_BUDGET_USD}, probe ${PROBE_BUDGET_USD})
  --no-pr            fetch the PR description but do not open the pull request
  --help             show this text

Environment:
  ISSUE_AGENT_GITHUB_TOKEN   required. Fine-grained GitHub token for this repository,
                             Contents: read and write. Used only to mount the repository.
  ISSUE_AGENT_ID             optional. Overrides the agent ID from claude-lock.json.
  ISSUE_AGENT_ENVIRONMENT_ID optional. Overrides the environment ID from claude-lock.json.
  ISSUE_AGENT_WORKSPACE      optional. Console workspace ID for the session link
                             (default: the workspace recorded in claude-lock.json).
`;

// Starter rubric: tune the criteria as real runs show what the grader rewards
// and what it misses.
export const STARTER_RUBRIC = `# Issue-to-PR rubric (starter, tune the criteria)

Either every criterion in "Implemented" holds, or the single criterion in "Blocked" holds.

## Implemented
- A branch named \`agent/issue-<number>\` exists on \`origin\`, and no commit was made to \`main\`.
- The change covers every item the issue lists as proposed work or acceptance criteria, or the pull request description names each item left out and why.
- \`cargo check --workspace --all-targets --locked\` passes, and the description shows the command and its result.
- \`cargo clippy --workspace --all-targets --locked\` passes with no new warnings, and the description shows the command and its result.
- \`cargo test -p <package> --locked\` passes for every package the change touches, and new or changed behaviour has a test.
- The change adds no \`unwrap\`, \`todo!\`, \`dbg!\` or \`unsafe\`, and nothing under \`.github/workflows/\` or \`release/\` is modified.
- Every document that \`CLAUDE.md\` maps to the changed surface is updated in the same branch, or the description states the gap.
- The change adds no third-party inference API, telemetry or analytics, and no test depends on \`AGENTPALACE_EMBED_ALLOW_DOWNLOADS\`.
- \`/mnt/session/outputs/pr.md\` exists. Its first line is a pull request title; the body has a summary, \`Closes #<number>\`, the verification commands with results, any decisions for review, and anything left unverified.

## Blocked
- No branch was pushed, and \`/mnt/session/outputs/pr.md\` starts with \`BLOCKED:\` followed by the reason, what was found in the code, and the specific decision the maintainer needs to make.
`;

export const PROBE_MESSAGE = `This is a setup probe. Do not start any task and do not change any file in the repository.

Report, as a short list:
1. The version of each of rustc, cargo, protoc, cc and git, or "missing".
2. Whether ${REPO_MOUNT_PATH} exists, and its HEAD commit and branch.
3. Whether \`git ls-remote origin HEAD\` succeeds there.
4. Whether \`git push --dry-run origin HEAD:refs/heads/agent/probe\` succeeds there. It is a dry run; do not push for real.
5. If cargo is present, whether \`cargo fetch --locked\` succeeds there. If it fails, name the host that was refused.
6. If cargo is missing, whether \`curl -sSf https://sh.rustup.rs -o /dev/null\` succeeds.
7. CPU count, memory and free disk space.

Give the exact error text for anything that fails.`;

/**
 * Parse command-line arguments.
 * @param {string[]} argv arguments after the script name
 */
export function parseArgs(argv) {
  const options = { probe: false, openPr: true, budgetUsd: undefined, issue: undefined, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--probe') {
      options.probe = true;
    } else if (arg === '--no-pr') {
      options.openPr = false;
    } else if (arg === '--budget-usd') {
      i += 1;
      const value = Number(argv[i]);
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error('--budget-usd needs a positive number');
      }
      options.budgetUsd = value;
    } else if (/^#?\d+$/.test(arg) && options.issue === undefined) {
      options.issue = Number(arg.replace('#', ''));
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!options.help) {
    if (options.probe && options.issue !== undefined) {
      throw new Error('Pass an issue number or --probe, not both');
    }
    if (!options.probe && options.issue === undefined) {
      throw new Error('Pass an issue number, or --probe');
    }
  }
  if (options.budgetUsd === undefined) {
    options.budgetUsd = options.probe ? PROBE_BUDGET_USD : DEFAULT_BUDGET_USD;
  }
  return options;
}

/**
 * Session budget object. The API takes the amount as an integer string in cents.
 * @param {number} usd
 */
export function budgetFromUsd(usd) {
  const cents = Math.round(usd * 100);
  if (!Number.isInteger(cents) || cents <= 0) {
    throw new Error(`Budget must be at least one cent, got ${usd}`);
  }
  return { type: 'limit', max_list_cost: { amount: String(cents), currency: 'USD' } };
}

/** @param {number} issue */
export function branchForIssue(issue) {
  return `agent/issue-${issue}`;
}

/**
 * The first message of a session: the issue as the agent should see it.
 * @param {{number:number,title:string,body?:string,state?:string,url?:string,comments?:Array<{author?:{login?:string},createdAt?:string,body?:string}>}} issue
 * @param {string} repo owner/name
 */
export function buildIssueMessage(issue, repo) {
  const lines = [
    `Implement GitHub issue #${issue.number} in ${repo}.`,
    '',
    '<issue>',
    `Number: ${issue.number}`,
    `Title: ${issue.title}`,
  ];
  if (issue.state) lines.push(`State: ${issue.state}`);
  if (issue.url) lines.push(`URL: ${issue.url}`);
  lines.push('', (issue.body ?? '').trim() || '(no description)');
  const comments = issue.comments ?? [];
  if (comments.length > 0) {
    lines.push('', 'Comments, oldest first:');
    for (const comment of comments) {
      const author = comment.author?.login ?? 'unknown';
      const when = comment.createdAt ?? 'unknown date';
      lines.push('', `--- ${author} on ${when}`, (comment.body ?? '').trim());
    }
  }
  lines.push('</issue>');
  return lines.join('\n');
}

/** @param {number} issue */
export function outcomeDescription(issue) {
  return `Implement GitHub issue #${issue} on branch ${branchForIssue(issue)}, push it, and write the pull request description to /mnt/session/outputs/pr.md. If the issue needs a maintainer decision first, write the BLOCKED report there instead.`;
}

/**
 * Split the agent's pr.md into a title and a body.
 * @param {string} text
 * @returns {{blocked:boolean,title:string,body:string}}
 */
export function splitPrFile(text) {
  const normalised = text.replace(/\r\n/g, '\n').trim();
  if (normalised === '') {
    throw new Error('pr.md is empty');
  }
  const newline = normalised.indexOf('\n');
  const firstLine = (newline === -1 ? normalised : normalised.slice(0, newline)).trim();
  const body = newline === -1 ? '' : normalised.slice(newline + 1).trim();
  const title = firstLine.replace(/^#+\s*/, '').trim();
  const blocked = /^BLOCKED\b/i.test(title);
  return { blocked, title, body };
}

/**
 * Read a resource ID out of the lock file `ant apply` writes.
 * @param {unknown} lock parsed claude-lock.json
 * @param {string} key resource path as the plan printed it
 */
export function idFromLock(lock, key) {
  const id = lock?.resources?.[key]?.id;
  return typeof id === 'string' && id !== '' ? id : undefined;
}

/**
 * True when the event ends the run: terminated, or idle for a reason other
 * than waiting on this client.
 * @param {{type:string,stop_reason?:{type?:string}}} event
 */
export function isTerminal(event) {
  if (event.type === 'session.status_terminated') return true;
  if (event.type === 'session.status_idle') {
    return event.stop_reason?.type !== 'requires_action';
  }
  return false;
}

/**
 * IDs of the paused tool calls that already have an answer on record.
 * @param {Array<{type:string,tool_use_id?:string}>} events session history
 * @returns {Set<string>}
 */
export function confirmedToolUseIds(events) {
  const ids = new Set();
  for (const event of events) {
    if (event.type === 'user.tool_confirmation' && typeof event.tool_use_id === 'string') {
      ids.add(event.tool_use_id);
    }
  }
  return ids;
}

/**
 * Run `step` until it returns true or the attempts run out, waiting between tries.
 * @param {() => Promise<boolean>} step
 * @param {{attempts:number,delayMs:number,sleep?:(ms:number)=>Promise<void>}} options
 * @returns {Promise<boolean>} whether a step succeeded
 */
export async function pollUntil(step, { attempts, delayMs, sleep }) {
  const wait = sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await wait(delayMs);
    if (await step()) return true;
  }
  return false;
}

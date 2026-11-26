#!/usr/bin/env node
// Runs one session of the issue-to-PR Managed Agent.
//
// The agent and environment are defined in ../agents and ../environments and
// created with `ant apply` (see README.md). This script only starts a session
// against the stored IDs; it never creates or changes an agent.

import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import Anthropic from '@anthropic-ai/sdk';

import {
  AGENT_LOCK_KEY,
  ENVIRONMENT_LOCK_KEY,
  PROBE_MESSAGE,
  REPO_MOUNT_PATH,
  STARTER_RUBRIC,
  USAGE,
  branchForIssue,
  budgetFromUsd,
  buildIssueMessage,
  confirmedToolUseIds,
  idFromLock,
  isTerminal,
  outcomeDescription,
  parseArgs,
  pollUntil,
  splitPrFile,
} from './lib.mjs';

const run = promisify(execFile);
const toolDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANAGED_AGENTS_BETA = 'managed-agents-2026-04-01';
const MAX_RECONNECTS = 5;

/** Run a CLI without a shell and return its stdout. */
async function cli(command, args) {
  const { stdout } = await run(command, args, { cwd: toolDir, maxBuffer: 16 * 1024 * 1024 });
  return stdout;
}

async function loadIds() {
  let lock;
  try {
    lock = JSON.parse(await readFile(path.join(toolDir, 'claude-lock.json'), 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const agentId = process.env.ISSUE_AGENT_ID || idFromLock(lock, AGENT_LOCK_KEY);
  const environmentId =
    process.env.ISSUE_AGENT_ENVIRONMENT_ID || idFromLock(lock, ENVIRONMENT_LOCK_KEY);
  if (!agentId || !environmentId) {
    throw new Error(
      'No agent or environment ID found. Run `ant apply` in tools/issue-agent first (see README.md), ' +
        'or set ISSUE_AGENT_ID and ISSUE_AGENT_ENVIRONMENT_ID.',
    );
  }
  // The Console link needs the workspace the resources were created in.
  const workspace = process.env.ISSUE_AGENT_WORKSPACE || lock?.origin?.workspace_id || 'default';
  return { agentId, environmentId, workspace };
}

async function loadRepo() {
  const repo = JSON.parse(await cli('gh', ['repo', 'view', '--json', 'nameWithOwner,url']));
  return { name: repo.nameWithOwner, url: repo.url };
}

async function loadIssue(number) {
  return JSON.parse(
    await cli('gh', [
      'issue',
      'view',
      String(number),
      '--json',
      'number,title,body,state,url,comments',
    ]),
  );
}

/** Decide a paused tool call. Asks at a terminal; denies when nobody is there. */
async function approve(event) {
  const summary = JSON.stringify(event.input ?? {}).slice(0, 600);
  console.log(`\n[paused] ${event.name} wants to run: ${summary}`);
  if (!process.stdin.isTTY) {
    console.log('[paused] no terminal attached, denying');
    return false;
  }
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await prompt.question('Allow this call? [y/N] ');
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    prompt.close();
  }
}

/** Print one event and answer it when it is waiting on this client. */
async function handle(client, sessionId, event, state) {
  switch (event.type) {
    case 'agent.message':
      for (const block of event.content ?? []) {
        if (block.type === 'text') process.stdout.write(`${block.text}\n`);
      }
      break;
    case 'agent.tool_use':
    case 'agent.mcp_tool_use': {
      if (event.evaluated_permission === 'deny') {
        console.log(`[denied by policy] ${event.name}`);
      } else if (event.evaluated_permission === 'ask') {
        // Already answered, in this process or before a reconnect.
        if (state.confirmed.has(event.id)) break;
        const allowed = await approve(event);
        await client.beta.sessions.events.send(sessionId, {
          events: [
            allowed
              ? { type: 'user.tool_confirmation', tool_use_id: event.id, result: 'allow' }
              : {
                  type: 'user.tool_confirmation',
                  tool_use_id: event.id,
                  result: 'deny',
                  deny_message: 'Not approved by the person running this session.',
                },
          ],
        });
        state.confirmed.add(event.id);
      } else {
        const detail = event.input?.command ?? event.input?.file_path ?? event.input?.pattern ?? '';
        console.log(`[${event.name}] ${String(detail).split('\n')[0].slice(0, 120)}`);
      }
      break;
    }
    case 'user.tool_confirmation':
      state.confirmed.add(event.tool_use_id);
      break;
    case 'span.outcome_evaluation_end':
      console.log(`\n[grader] iteration ${event.iteration}: ${event.result}`);
      if (event.explanation) console.log(`[grader] ${event.explanation}`);
      state.lastOutcome = event.result;
      break;
    case 'session.error':
      console.error(`\n[session error] ${event.error?.message ?? JSON.stringify(event.error)}`);
      break;
    case 'session.status_idle':
      state.stopReason = event.stop_reason?.type;
      break;
    case 'session.status_terminated':
      state.stopReason = 'terminated';
      break;
    default:
      break;
  }
}

/**
 * Follow a session to its end. On every (re)connect the stream is opened first
 * and the history is read second, so nothing emitted in between is lost;
 * events are deduplicated by ID.
 */
async function follow(client, sessionId, state) {
  const seen = new Set();
  // An event counts as handled only once handle() returns. If answering a
  // paused call fails mid-send, the event is handled again after the reconnect.
  const handleOnce = async (event) => {
    if (seen.has(event.id)) return;
    await handle(client, sessionId, event, state);
    seen.add(event.id);
  };
  for (let attempt = 0; attempt <= MAX_RECONNECTS; attempt += 1) {
    let stream;
    try {
      stream = await client.beta.sessions.events.stream(sessionId);
      const history = [];
      for await (const event of client.beta.sessions.events.list(sessionId)) {
        history.push(event);
      }
      // A confirmation that reached the server before a dropped connection is
      // in the history; record it first so the call is not answered twice.
      for (const id of confirmedToolUseIds(history)) state.confirmed.add(id);
      let finished = false;
      for (const event of history) {
        await handleOnce(event);
        // History can hold trailing events after the final idle, so track the
        // last status change instead of the last event.
        if (isTerminal(event)) finished = true;
        else if (event.type === 'session.status_running') finished = false;
      }
      if (finished) return;
      for await (const event of stream) {
        await handleOnce(event);
        if (isTerminal(event)) return;
      }
      console.error('[stream] closed before the session finished, reconnecting');
    } catch (error) {
      if (error instanceof Anthropic.APIConnectionError) {
        console.error(`[stream] connection lost (${error.message}), reconnecting`);
      } else {
        throw error;
      }
    } finally {
      // Release the connection on every exit, including the early return when
      // the history already shows the session finished. An open stream would
      // otherwise keep the process alive.
      stream?.controller.abort();
    }
  }
  throw new Error(`Lost the event stream ${MAX_RECONNECTS + 1} times; the session may still be running.`);
}

/** Download what the agent wrote to /mnt/session/outputs/. */
async function fetchOutputs(client, sessionId, outDir, required) {
  await mkdir(outDir, { recursive: true });
  const saved = new Map();
  // Outputs are indexed a few seconds after the session goes idle, and not
  // necessarily all at once, so keep listing until the required file shows up.
  await pollUntil(
    async () => {
      for await (const file of client.beta.files.list({
        scope_id: sessionId,
        betas: [MANAGED_AGENTS_BETA],
      })) {
        const name = path.basename(file.filename);
        if (saved.has(name)) continue;
        const response = await client.beta.files.download(file.id);
        const target = path.join(outDir, name);
        await writeFile(target, Buffer.from(await response.arrayBuffer()));
        saved.set(name, target);
      }
      return saved.has(required);
    },
    { attempts: 8, delayMs: 2000 },
  );
  return saved;
}

async function branchExists(repoName, branch) {
  try {
    await cli('gh', ['api', `repos/${repoName}/git/ref/heads/${branch}`, '--silent']);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`${error.message}\n\n${USAGE}`);
    return 2;
  }
  if (options.help) {
    console.log(USAGE);
    return 0;
  }

  const token = process.env.ISSUE_AGENT_GITHUB_TOKEN;
  if (!token) {
    console.error('ISSUE_AGENT_GITHUB_TOKEN is not set.\n');
    console.error(USAGE);
    return 2;
  }

  const { agentId, environmentId, workspace } = await loadIds();
  const repo = await loadRepo();
  const client = new Anthropic();

  let title;
  let initialEvents;
  if (options.probe) {
    title = `Sandbox probe for ${repo.name}`;
    initialEvents = [{ type: 'user.message', content: [{ type: 'text', text: PROBE_MESSAGE }] }];
  } else {
    const issue = await loadIssue(options.issue);
    if (issue.state && issue.state !== 'OPEN') {
      console.error(`Issue #${issue.number} is ${issue.state}; nothing to do.`);
      return 2;
    }
    title = `Issue #${issue.number}: ${issue.title}`.slice(0, 200);
    // The issue text goes first as a message; the outcome that follows tells the
    // harness what "done" means and starts the grade-and-revise loop.
    initialEvents = [
      {
        type: 'user.message',
        content: [{ type: 'text', text: buildIssueMessage(issue, repo.name) }],
      },
      {
        type: 'user.define_outcome',
        description: outcomeDescription(issue.number),
        rubric: { type: 'text', content: STARTER_RUBRIC },
        max_iterations: 3,
      },
    ];
  }

  const session = await client.beta.sessions.create({
    agent: agentId,
    environment_id: environmentId,
    title,
    budget: budgetFromUsd(options.budgetUsd),
    resources: [
      {
        type: 'github_repository',
        url: repo.url,
        mount_path: REPO_MOUNT_PATH,
        authorization_token: token,
        checkout: { type: 'branch', name: 'main' },
      },
    ],
    initial_events: initialEvents,
  });

  console.log(`Session ${session.id} started with a $${options.budgetUsd} cap.`);
  console.log(`Watch: https://platform.claude.com/workspaces/${workspace}/sessions/${session.id}\n`);

  const state = { stopReason: undefined, lastOutcome: undefined, confirmed: new Set() };
  await follow(client, session.id, state);

  const finished = await client.beta.sessions.retrieve(session.id);
  const cost = finished.usage?.list_cost;
  const spent = cost ? `$${(Number(cost.amount) / 100).toFixed(2)} at list price` : 'cost not reported';
  console.log(`\nSession ended: ${state.stopReason ?? finished.status}; ${spent}.`);
  if (state.stopReason === 'budget_reached') {
    console.error('The session paused at its spend cap. Raise the budget in the Console to resume it.');
    return 1;
  }
  if (state.stopReason === 'retries_exhausted' || state.stopReason === 'terminated') {
    console.error('The session did not finish normally. Open the Watch link for the cause.');
    return 1;
  }
  if (options.probe) return 0;

  const outDir = path.join(toolDir, 'out', `issue-${options.issue}`);
  const outputs = await fetchOutputs(client, session.id, outDir, 'pr.md');
  const prFile = outputs.get('pr.md');
  if (!prFile) {
    console.error(`The agent wrote no pr.md. Files fetched: ${[...outputs.keys()].join(', ') || 'none'}.`);
    return 1;
  }

  const pr = splitPrFile(await readFile(prFile, 'utf8'));
  if (pr.blocked) {
    console.log(`\n${pr.title}\nThe agent stopped for a maintainer decision. Its report is at ${prFile}`);
    return 3;
  }
  if (state.lastOutcome && state.lastOutcome !== 'satisfied') {
    console.log(`\nThe grader's last verdict was "${state.lastOutcome}", not "satisfied". Read ${prFile} before trusting the branch.`);
  }

  const branch = branchForIssue(options.issue);
  if (!(await branchExists(repo.name, branch))) {
    console.error(`Branch ${branch} is not on GitHub, so no pull request was opened. Description saved at ${prFile}`);
    return 1;
  }
  if (!options.openPr) {
    console.log(`\nBranch ${branch} is pushed. Description saved at ${prFile}; --no-pr was set, so no pull request was opened.`);
    return 0;
  }

  const bodyFile = path.join(outDir, 'pr-body.md');
  await writeFile(bodyFile, `${pr.body}\n`);
  const url = await cli('gh', [
    'pr',
    'create',
    '--draft',
    '--base',
    'main',
    '--head',
    branch,
    '--title',
    pr.title,
    '--body-file',
    bodyFile,
  ]);
  console.log(`\nDraft pull request opened: ${url.trim()}`);
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  // Most specific first: the fix differs for each.
  if (error instanceof Anthropic.AuthenticationError) {
    console.error('Not authenticated with the Claude API. Run `ant auth login`, or set ANTHROPIC_API_KEY.');
  } else if (error instanceof Anthropic.NotFoundError) {
    console.error(`Not found: ${error.message}\nThe agent or environment ID may belong to another workspace.`);
  } else if (error instanceof Anthropic.RateLimitError) {
    console.error(`Rate limited: ${error.message}\nWait and run it again.`);
  } else if (error instanceof Anthropic.APIError) {
    console.error(`Claude API error ${error.status ?? ''}: ${error.message}`);
  } else {
    console.error(error.message ?? error);
  }
  process.exitCode = 1;
}

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_BUDGET_USD,
  PROBE_BUDGET_USD,
  branchForIssue,
  budgetFromUsd,
  buildIssueMessage,
  idFromLock,
  isTerminal,
  parseArgs,
  splitPrFile,
} from '../src/lib.mjs';

test('parseArgs reads an issue number with the default budget', () => {
  const options = parseArgs(['109']);
  assert.equal(options.issue, 109);
  assert.equal(options.probe, false);
  assert.equal(options.openPr, true);
  assert.equal(options.budgetUsd, DEFAULT_BUDGET_USD);
});

test('parseArgs accepts a leading hash, --no-pr and a budget', () => {
  const options = parseArgs(['#89', '--no-pr', '--budget-usd', '4.5']);
  assert.equal(options.issue, 89);
  assert.equal(options.openPr, false);
  assert.equal(options.budgetUsd, 4.5);
});

test('parseArgs gives the probe its own smaller budget', () => {
  const options = parseArgs(['--probe']);
  assert.equal(options.probe, true);
  assert.equal(options.issue, undefined);
  assert.equal(options.budgetUsd, PROBE_BUDGET_USD);
});

test('parseArgs rejects missing, conflicting and unknown arguments', () => {
  assert.throws(() => parseArgs([]), /issue number/);
  assert.throws(() => parseArgs(['109', '--probe']), /not both/);
  assert.throws(() => parseArgs(['109', '--force']), /Unknown argument/);
  assert.throws(() => parseArgs(['109', '--budget-usd', '0']), /positive number/);
  assert.throws(() => parseArgs(['109', '--budget-usd']), /positive number/);
});

test('parseArgs lets --help through without an issue', () => {
  assert.equal(parseArgs(['--help']).help, true);
});

test('budgetFromUsd writes whole cents as a string', () => {
  assert.deepEqual(budgetFromUsd(10), {
    type: 'limit',
    max_list_cost: { amount: '1000', currency: 'USD' },
  });
  assert.equal(budgetFromUsd(0.5).max_list_cost.amount, '50');
  assert.equal(budgetFromUsd(4.35).max_list_cost.amount, '435');
  assert.throws(() => budgetFromUsd(0.001), /at least one cent/);
});

test('branchForIssue names the branch the agent is told to push', () => {
  assert.equal(branchForIssue(109), 'agent/issue-109');
});

test('buildIssueMessage includes the body and comments in order', () => {
  const text = buildIssueMessage(
    {
      number: 109,
      title: 'Stale WARN',
      state: 'OPEN',
      url: 'https://example.test/issues/109',
      body: 'The warning repeats.\r\n',
      comments: [
        { author: { login: 'first' }, createdAt: '2026-01-01', body: 'one' },
        { author: { login: 'second' }, createdAt: '2026-01-02', body: 'two' },
      ],
    },
    'owner/repo',
  );
  assert.match(text, /^Implement GitHub issue #109 in owner\/repo\./);
  assert.match(text, /Title: Stale WARN/);
  assert.match(text, /The warning repeats\./);
  assert.ok(text.indexOf('--- first on 2026-01-01') < text.indexOf('--- second on 2026-01-02'));
  assert.ok(text.endsWith('</issue>'));
});

test('buildIssueMessage copes with an empty body and no comments', () => {
  const text = buildIssueMessage({ number: 1, title: 'T', body: '' }, 'owner/repo');
  assert.match(text, /\(no description\)/);
  assert.doesNotMatch(text, /Comments, oldest first/);
});

test('splitPrFile separates the title from the body', () => {
  const pr = splitPrFile('# Finalize stale diary runs\r\n\r\nCloses #109\r\n\r\nDetails.\r\n');
  assert.equal(pr.blocked, false);
  assert.equal(pr.title, 'Finalize stale diary runs');
  assert.equal(pr.body, 'Closes #109\n\nDetails.');
});

test('splitPrFile recognises a blocked report', () => {
  const pr = splitPrFile('BLOCKED: downgrade behaviour is undecided\n\nNeeds a choice.');
  assert.equal(pr.blocked, true);
  assert.equal(pr.title, 'BLOCKED: downgrade behaviour is undecided');
});

test('splitPrFile handles a title with no body and rejects an empty file', () => {
  assert.deepEqual(splitPrFile('Only a title'), { blocked: false, title: 'Only a title', body: '' });
  assert.throws(() => splitPrFile('  \n'), /empty/);
});

test('idFromLock reads an ID and tolerates a missing lock or entry', () => {
  const lock = { resources: { './agents/issue-to-pr.md': { id: 'agent_123' } } };
  assert.equal(idFromLock(lock, './agents/issue-to-pr.md'), 'agent_123');
  assert.equal(idFromLock(lock, './environments/rust-dev.yaml'), undefined);
  assert.equal(idFromLock(undefined, './agents/issue-to-pr.md'), undefined);
});

test('isTerminal keeps waiting only while the session needs this client', () => {
  assert.equal(isTerminal({ type: 'session.status_terminated' }), true);
  assert.equal(isTerminal({ type: 'session.status_idle', stop_reason: { type: 'end_turn' } }), true);
  assert.equal(isTerminal({ type: 'session.status_idle', stop_reason: { type: 'budget_reached' } }), true);
  assert.equal(
    isTerminal({ type: 'session.status_idle', stop_reason: { type: 'requires_action' } }),
    false,
  );
  assert.equal(isTerminal({ type: 'agent.message' }), false);
});

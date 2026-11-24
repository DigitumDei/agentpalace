import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { PalaceClient, PalaceHttpError } from '../src/palace-client.mjs';

function startMockServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsedBody = body ? JSON.parse(body) : null;
      const result = await handler({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: parsedBody,
      });
      res.writeHead(result.status ?? 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.json ?? {}));
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test('PalaceClient sends exact /v1/coordination/* paths, queries, headers, and bodies', async () => {
  const seen = [];
  const server = await startMockServer((req) => {
    seen.push(req);
    if (req.url === '/v1/health') {
      return { status: 200, json: { status: 'ok' } };
    }
    if (req.url.startsWith('/v1/coordination/tasks?')) {
      return { status: 200, json: { tasks: [{ task_id: 'task_1', revision: 1 }], next_cursor: null } };
    }
    if (req.url === '/v1/coordination/tasks/task_1/claim') {
      return { status: 200, json: { task_id: 'task_1', state: 'running', revision: 2 } };
    }
    if (req.url.startsWith('/v1/coordination/inbox?')) {
      return { status: 200, json: { messages: [{ message_id: 'msg_1', task_id: 'task_1' }], next_cursor: null } };
    }
    if (req.url === '/v1/coordination/tasks/task_conflict/claim') {
      return { status: 409, json: { code: 'revision_conflict', message: 'revision mismatch' } };
    }
    return { status: 404, json: { error: 'not found' } };
  });

  try {
    const client = new PalaceClient({ baseUrl: server.baseUrl, token: 'secret-tok' });

    const health = await client.health();
    assert.equal(health.status, 'ok');
    assert.equal(seen[0].headers.authorization, undefined);

    const listed = await client.listTasks({ state: 'pending', wing: 'wing_agents', limit: 10 });
    assert.equal(listed.tasks.length, 1);
    assert.equal(seen[1].headers.authorization, 'Bearer secret-tok');
    assert.match(seen[1].url, /state=pending/);
    assert.match(seen[1].url, /wing=wing_agents/);

    const claimed = await client.claimTask('task_1', {
      expectedRevision: 1,
      leaseSeconds: 300,
      worker: 'claude',
    });
    assert.equal(claimed.revision, 2);
    assert.deepEqual(seen[2].body, {
      expected_revision: 1,
      lease_seconds: 300,
      worker: 'claude',
    });

    const inbox = await client.readInbox({ recipient: 'claude', unacknowledgedOnly: true });
    assert.equal(inbox.messages.length, 1);
    assert.match(seen[3].url, /recipient=claude/);
    assert.match(seen[3].url, /unacknowledged_only=true/);

    await assert.rejects(
      () => client.claimTask('task_conflict', { expectedRevision: 1, leaseSeconds: 300, worker: 'claude' }),
      (err) => err instanceof PalaceHttpError && err.status === 409 && err.code === 'revision_conflict',
    );
  } finally {
    await server.close();
  }
});

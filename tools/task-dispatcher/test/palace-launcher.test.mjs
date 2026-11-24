import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { ensurePalaceServer, resolveLoopbackBind } from '../src/palace-launcher.mjs';
import { PalaceClient } from '../src/palace-client.mjs';

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

test('resolveLoopbackBind accepts loopback URLs and rejects remote hosts', () => {
  assert.equal(resolveLoopbackBind('http://127.0.0.1:8765'), '127.0.0.1:8765');
  assert.equal(resolveLoopbackBind('http://localhost:9000'), '127.0.0.1:9000');
  assert.equal(resolveLoopbackBind('https://palace.example.com'), null);
});

test('ensurePalaceServer returns immediately when palace is already healthy', async () => {
  const client = {
    token: 'existing',
    async health() {
      return { status: 'ok' };
    },
  };
  const handle = await ensurePalaceServer({
    config: { palace: { baseUrl: 'http://127.0.0.1:8765', autoStart: { enabled: true } } },
    client,
    logger: { log() {}, warn() {}, error() {} },
  });
  assert.equal(handle.started, false);
  assert.equal(handle.token, 'existing');
  await handle.stop();
});

test('ensurePalaceServer refuses to auto-start non-loopback URLs', async () => {
  const client = {
    token: '',
    async health() {
      throw new Error('ECONNREFUSED');
    },
  };
  await assert.rejects(
    () =>
      ensurePalaceServer({
        config: {
          palace: { baseUrl: 'http://192.168.1.50:8765', autoStart: { enabled: true } },
          paths: { logDir: os.tmpdir() },
        },
        client,
        logger: { log() {}, warn() {}, error() {} },
      }),
    /non-loopback/,
  );
});

test('ensurePalaceServer spawns local server, creates ephemeral token file, waits for health, and stops cleanly', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ap-launcher-'));
  try {
    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const fakeServerScript = path.join(tmpDir, 'fake-palace.mjs');

    // Fake `agentpalace serve --bind <addr> --token-file <file>` implemented in Node.
    await fs.writeFile(
      fakeServerScript,
      `import http from 'node:http';
import fs from 'node:fs';
const args = process.argv.slice(2);
const bindIdx = args.indexOf('--bind');
const tokenIdx = args.indexOf('--token-file');
const [host, portStr] = args[bindIdx + 1].split(':');
const tokenEntries = JSON.parse(fs.readFileSync(args[tokenIdx + 1], 'utf8'));
const expectedToken = tokenEntries[0].token;
const server = http.createServer((req, res) => {
  if (req.url === '/v1/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  if (req.headers.authorization === 'Bearer ' + expectedToken) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ tasks: [] }));
    return;
  }
  res.writeHead(401, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'unauthorized' }));
});
server.listen(Number(portStr), host);
`,
      'utf8',
    );

    const client = new PalaceClient({ baseUrl, token: '', requestTimeoutMs: 2000 });
    const handle = await ensurePalaceServer({
      config: {
        palace: {
          baseUrl,
          token: '',
          autoStart: {
            enabled: true,
            command: process.execPath,
            palacePath: '',
            tokenFile: '',
            startupTimeoutMs: 5000,
            keepAlive: false,
            extraArgs: [],
          },
        },
        paths: { logDir: path.join(tmpDir, 'logs') },
      },
      client,
      logger: { log() {}, warn() {}, error() {} },
      spawnImpl: (cmd, args, opts) => spawn(cmd, [fakeServerScript, ...args], opts),
    });

    assert.equal(handle.started, true);
    assert.ok(handle.pid > 0);
    assert.ok(handle.token.length >= 32);
    assert.equal(client.token, handle.token);

    // Authenticated coordination request succeeds using the auto-generated ephemeral token!
    const listed = await client.listTasks({ state: 'pending' });
    assert.deepEqual(listed.tasks, []);

    await handle.stop();
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

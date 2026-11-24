import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { killProcessTree } from './process-runner.mjs';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/**
 * Parse a loopback `baseUrl` into a `host:port` bind address for `agentpalace serve --bind`.
 * Returns `null` if the URL is not a loopback address.
 */
export function resolveLoopbackBind(baseUrl) {
  const parsed = new URL(baseUrl);
  const host = parsed.hostname.toLowerCase();
  if (!LOOPBACK_HOSTS.has(host)) {
    return null;
  }
  const bindHost = host === 'localhost' ? '127.0.0.1' : host;
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  return `${bindHost}:${port}`;
}

/**
 * Resolve the `agentpalace` binary path:
 * 1. Explicit `autoStart.command` if provided
 * 2. Default install location `~/.agentpalace/bin/agentpalace(.exe)` if present
 * 3. Fallback to `agentpalace` on `PATH`
 */
export async function resolvePalaceBinary(configuredCommand) {
  if (configuredCommand && configuredCommand.trim()) {
    return configuredCommand.trim();
  }
  const exeName = process.platform === 'win32' ? 'agentpalace.exe' : 'agentpalace';
  const defaultPath = path.join(os.homedir(), '.agentpalace', 'bin', exeName);
  try {
    await fsp.access(defaultPath);
    return defaultPath;
  } catch {
    return 'agentpalace';
  }
}

function gracefulStopChild(child, alreadyExited, graceMs = 3000) {
  if (alreadyExited() || !child?.pid) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve();
    };

    child.once('exit', finish);

    if (process.platform === 'win32') {
      // Request graceful termination first, then force-kill tree if still alive.
      execFile('taskkill', ['/PID', String(child.pid), '/T'], { windowsHide: true }, () => {});
    } else {
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        try {
          child.kill('SIGTERM');
        } catch {
          finish();
          return;
        }
      }
    }

    const timer = setTimeout(() => {
      if (!alreadyExited()) {
        killProcessTree(child);
      }
      finish();
    }, graceMs);
    timer.unref?.();
  });
}

/**
 * Ensure an AgentPalace HTTP server is reachable at `config.palace.baseUrl`.
 *
 * - If `/v1/health` already succeeds, returns immediately without spawning anything.
 * - If unreachable and `config.palace.autoStart.enabled` is true (and `baseUrl` is
 *   loopback), spawns `agentpalace serve`, waits for `/v1/health` readiness, and
 *   returns a `stop()` handle that cleanly tears down the child process on exit.
 * - If neither `palace.token` nor `autoStart.tokenFile` is configured (and
 *   `keepAlive` is false), generates an ephemeral `0600` bearer token file for
 *   the spawned local server and sets `client.token` automatically.
 */
export async function ensurePalaceServer({
  config,
  client,
  logger = console,
  spawnImpl = spawn,
}) {
  // 1. Check if already running.
  try {
    await client.health();
    return { started: false, pid: null, token: client.token, stop: async () => {} };
  } catch {
    // Not reachable; proceed to auto-start if enabled.
  }

  const auto = config.palace.autoStart;
  if (!auto?.enabled) {
    throw new Error(
      `AgentPalace server at ${config.palace.baseUrl} is unreachable and palace.autoStart.enabled is false.`,
    );
  }

  const bindAddr = resolveLoopbackBind(config.palace.baseUrl);
  if (!bindAddr) {
    throw new Error(
      `Refusing to auto-start AgentPalace for non-loopback URL "${config.palace.baseUrl}". Start the remote server separately or point baseUrl to 127.0.0.1.`,
    );
  }

  let ephemeralTokenFile = null;
  let activeToken = client.token;

  if (auto.keepAlive && !auto.tokenFile && !activeToken) {
    throw new Error(
      'Config error: palace.autoStart.keepAlive=true requires a persistent palace.token (and optional tokenFile). An ephemeral generated token cannot be reused by the next dispatcher startup.',
    );
  }

  const command = await resolvePalaceBinary(auto.command);
  const args = ['serve', '--bind', bindAddr];
  if (auto.palacePath) {
    args.push('--palace', auto.palacePath);
  }

  if (auto.tokenFile) {
    args.push('--token-file', auto.tokenFile);
  } else if (!activeToken) {
    activeToken = crypto.randomBytes(32).toString('hex');
    ephemeralTokenFile = path.join(
      os.tmpdir(),
      `agentpalace-dispatcher-tokens-${process.pid}-${crypto.randomUUID()}.json`,
    );
    const payload = JSON.stringify(
      [{ name: 'dispatcher', token: activeToken, enabled: true }],
      null,
      2,
    );
    await fsp.writeFile(ephemeralTokenFile, payload, { encoding: 'utf8', mode: 0o600 });
    if (process.platform !== 'win32') {
      await fsp.chmod(ephemeralTokenFile, 0o600);
    }
    args.push('--token-file', ephemeralTokenFile);
    client.token = activeToken;
  }

  if (Array.isArray(auto.extraArgs) && auto.extraArgs.length > 0) {
    args.push(...auto.extraArgs);
  }

  const logPath = path.join(config.paths.logDir, 'agentpalace-serve.log');
  await fsp.mkdir(path.dirname(logPath), { recursive: true });
  await fsp.appendFile(
    logPath,
    `\n=== Auto-starting AgentPalace at ${new Date().toISOString()} ===\nCommand: ${command} ${args.join(' ')}\n\n`,
    'utf8',
  );

  logger.log(
    `[dispatcher] AgentPalace not reachable at ${config.palace.baseUrl}; starting "${command} ${args.join(' ')}"...`,
  );

  let logStream = null;
  let detachedLogFd = null;
  let stdio;

  if (auto.keepAlive) {
    // Redirect directly to a file descriptor so the child survives dispatcher exit
    // without EPIPE or keeping the parent event loop alive.
    detachedLogFd = fs.openSync(logPath, 'a');
    stdio = ['ignore', detachedLogFd, detachedLogFd];
  } else {
    logStream = fs.createWriteStream(logPath, { flags: 'a' });
    stdio = ['ignore', 'pipe', 'pipe'];
  }

  const child = spawnImpl(command, args, {
    env: { ...process.env, ...(auto.env ?? {}) },
    detached: auto.keepAlive || process.platform !== 'win32',
    windowsHide: true,
    stdio,
  });

  if (detachedLogFd !== null) {
    fs.closeSync(detachedLogFd);
    detachedLogFd = null;
  }

  let exited = false;
  let exitCode = null;
  let spawnErr = null;
  let stderrTail = '';

  child.stdout?.on('data', (chunk) => {
    logStream?.write(chunk);
  });
  child.stderr?.on('data', (chunk) => {
    const text = chunk.toString('utf8');
    stderrTail = (stderrTail + text).slice(-2048);
    logStream?.write(text);
  });
  child.on('error', (err) => {
    spawnErr = err;
    exited = true;
  });
  child.on('exit', (code) => {
    exited = true;
    exitCode = code;
  });

  const cleanup = async () => {
    await gracefulStopChild(child, () => exited);
    logStream?.end();
    if (ephemeralTokenFile) {
      await fsp.rm(ephemeralTokenFile, { force: true }).catch(() => {});
      ephemeralTokenFile = null;
    }
  };

  const deadline = Date.now() + auto.startupTimeoutMs;
  while (Date.now() < deadline) {
    if (spawnErr) {
      await cleanup();
      throw new Error(`Failed to spawn "${command}": ${spawnErr.message}`);
    }
    if (exited) {
      await cleanup();
      throw new Error(
        `AgentPalace exited early (code=${exitCode}) before becoming healthy. Check ${logPath}.${stderrTail ? `\nStderr: ${stderrTail.trim()}` : ''}`,
      );
    }
    try {
      await client.health();
      logger.log(`[dispatcher] AgentPalace is ready at ${config.palace.baseUrl} (pid=${child.pid}, log=${logPath}).`);
      if (auto.keepAlive) {
        child.unref?.();
      }
      return {
        started: true,
        pid: child.pid ?? null,
        token: activeToken,
        logPath,
        stop: async () => {
          if (auto.keepAlive) {
            logger.log(`[dispatcher] Leaving auto-started AgentPalace running (pid=${child.pid}, keepAlive=true).`);
            return;
          }
          logger.log(`[dispatcher] Stopping auto-started AgentPalace (pid=${child.pid})...`);
          await cleanup();
        },
      };
    } catch {
      await new Promise((r) => setTimeout(r, 300));
    }
  }

  await cleanup();
  throw new Error(
    `Timed out after ${auto.startupTimeoutMs}ms waiting for AgentPalace health at ${config.palace.baseUrl}/v1/health. Check ${logPath}.`,
  );
}

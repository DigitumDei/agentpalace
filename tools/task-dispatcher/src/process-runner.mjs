import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { MAX_TIMEOUT_MS } from './config.mjs';

/**
 * Kill a process and its entire child process tree on both Windows and POSIX.
 * Returns a Promise that resolves once the process tree has exited or been
 * forcibly terminated, keeping POSIX escalation referenced so `--once` runs
 * cannot exit with live descendants still running.
 */
export function killProcessTree(child, { graceMs = 5000 } = {}) {
  if (!child || !child.pid) return Promise.resolve();
  const pid = child.pid;

  if (process.platform === 'win32') {
    return new Promise((resolve) => {
      execFile('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, () => {
        resolve();
      });
    });
  }

  let useGroup = true;
  try {
    // Detached POSIX children lead their own process group (-pid).
    process.kill(-pid, 'SIGTERM');
  } catch (err) {
    if (err.code === 'ESRCH') {
      return Promise.resolve();
    }
    useGroup = false;
    try {
      child.kill('SIGTERM');
    } catch {
      return Promise.resolve();
    }
  }

  const targetPid = useGroup ? -pid : pid;
  const isAlive = () => {
    try {
      process.kill(targetPid, 0);
      return true;
    } catch (err) {
      return err.code === 'EPERM';
    }
  };

  return new Promise((resolve) => {
    const deadline = Date.now() + Math.max(0, graceMs);
    let escalated = false;

    const poll = setInterval(() => {
      if (!isAlive()) {
        clearInterval(poll);
        resolve();
        return;
      }
      if (!escalated && Date.now() >= deadline) {
        escalated = true;
        try {
          process.kill(targetPid, 'SIGKILL');
        } catch {
          try {
            child.kill('SIGKILL');
          } catch {
            clearInterval(poll);
            resolve();
            return;
          }
        }
      } else if (escalated && Date.now() >= deadline + 1000) {
        clearInterval(poll);
        resolve();
      }
    }, 50);
  });
}

/**
 * Resolve a bare command name on Windows by scanning `PATH` for `.exe`, `.com`,
 * `.ps1`, `.cmd`, `.bat` (preferring direct executables and `.ps1` over `.cmd`
 * so we avoid `shell: true`, Node DEP0190 warnings, and `cmd.exe` space splitting).
 */
function findWindowsExecutable(command, env = process.env) {
  if (command.includes('\\') || command.includes('/')) {
    return command;
  }

  const pathEntries = (env.PATH || env.Path || '').split(';').filter(Boolean);
  const hasExt = /\.[a-z0-9]+$/i.test(command);
  const exts = hasExt ? [''] : ['.exe', '.com', '.ps1', '.cmd', '.bat'];

  for (const dir of pathEntries) {
    for (const ext of exts) {
      const candidate = path.join(dir, command + ext);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return command;
}

/**
 * Resolve PowerShell binary on Windows: prefer `pwsh.exe` if on PATH, otherwise
 * fall back to built-in `powershell.exe` (available on stock Windows).
 */
function resolveWindowsPowerShell(env = process.env) {
  const pwsh = findWindowsExecutable('pwsh.exe', env);
  if (pwsh !== 'pwsh.exe') {
    return pwsh;
  }
  return 'powershell.exe';
}

/**
 * Resolve spawn specification across Windows and POSIX without `shell: true`
 * whenever a direct `.exe` or `.ps1` binary is available.
 */
export function resolveSpawnSpec(command, args, env = process.env) {
  if (process.platform !== 'win32') {
    return { cmd: command, args, useShell: false };
  }

  const resolved = findWindowsExecutable(command, env);
  const lower = resolved.toLowerCase();

  if (lower.endsWith('.ps1')) {
    return {
      cmd: resolveWindowsPowerShell(env),
      args: ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', resolved, ...args],
      useShell: false,
    };
  }
  if (lower.endsWith('.exe') || lower.endsWith('.com')) {
    return { cmd: resolved, args, useShell: false };
  }
  if (lower.endsWith('.cmd') || lower.endsWith('.bat')) {
    // Prefer a sibling .ps1 shim (npm installs both .cmd and .ps1) to avoid cmd.exe quoting.
    const ps1Sibling = resolved.replace(/\.(cmd|bat)$/i, '.ps1');
    if (fs.existsSync(ps1Sibling)) {
      return {
        cmd: resolveWindowsPowerShell(env),
        args: ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1Sibling, ...args],
        useShell: false,
      };
    }
    return { cmd: resolved, args, useShell: true };
  }

  return { cmd: resolved, args, useShell: false };
}

/**
 * Run an external agent harness with bounded log capture, timeout + tree kill,
 * and OS-safe prompt delivery via stdin or temp file.
 */
export async function runHarnessProcess({
  command,
  args = [],
  cwd,
  env = {},
  prompt,
  promptDelivery = 'stdin',
  timeoutMs = 1800000,
  logPath,
  onSpawn,
}) {
  let tempPromptFile = null;
  const finalArgs = [...args];
  const effectiveTimeoutMs = Math.min(
    MAX_TIMEOUT_MS,
    Math.max(1, typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) ? Math.floor(timeoutMs) : 1800000),
  );

  if (promptDelivery === 'file') {
    tempPromptFile = path.join(os.tmpdir(), `agentpalace-prompt-${process.pid}-${crypto.randomUUID()}.txt`);
    await fsp.writeFile(tempPromptFile, prompt, 'utf8');
    for (let i = 0; i < finalArgs.length; i++) {
      finalArgs[i] = finalArgs[i].replaceAll('{promptFile}', tempPromptFile);
    }
  }

  let logStream = null;
  if (logPath) {
    await fsp.mkdir(path.dirname(logPath), { recursive: true });
    logStream = fs.createWriteStream(logPath, { flags: 'a' });
    logStream.write(`\n=== Dispatch started at ${new Date().toISOString()} ===\n`);
    logStream.write(`Command: ${command} ${finalArgs.join(' ')}\nCWD: ${cwd}\n\n`);
  }

  const startedAt = Date.now();
  const mergedEnv = { ...process.env, ...env };
  const spec = resolveSpawnSpec(command, finalArgs, mergedEnv);

  try {
    return await new Promise((resolve) => {
      let timedOut = false;
      let settled = false;
      let killPromise = null;
      let stdoutTail = '';
      let stderrTail = '';
      const MAX_TAIL = 4096;

      const appendTail = (current, chunk) => {
        const next = current + chunk;
        return next.length > MAX_TAIL ? next.slice(next.length - MAX_TAIL) : next;
      };

      const child = spawn(spec.cmd, spec.args, {
        cwd,
        env: mergedEnv,
        shell: spec.useShell,
        detached: process.platform !== 'win32',
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      onSpawn?.(child);

      const timer = setTimeout(() => {
        timedOut = true;
        killPromise = killProcessTree(child);
      }, effectiveTimeoutMs);

      const finish = async (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (killPromise) {
          await killPromise.catch(() => {});
        }
        if (logStream) {
          logStream.write(
            `\n=== Dispatch ended at ${new Date().toISOString()} (exit=${result.exitCode}, timedOut=${result.timedOut}, durationMs=${result.durationMs}) ===\n`,
          );
          logStream.end();
        }
        resolve(result);
      };

      child.stdout?.on('data', (buf) => {
        const text = buf.toString('utf8');
        stdoutTail = appendTail(stdoutTail, text);
        logStream?.write(text);
      });

      child.stderr?.on('data', (buf) => {
        const text = buf.toString('utf8');
        stderrTail = appendTail(stderrTail, text);
        logStream?.write(text);
      });

      child.on('error', (err) => {
        void finish({
          pid: child.pid ?? null,
          exitCode: -1,
          signal: null,
          timedOut,
          durationMs: Date.now() - startedAt,
          error: err.message,
          stdoutTail,
          stderrTail,
          logPath: logPath ?? null,
        });
      });

      child.on('close', (code, signal) => {
        void finish({
          pid: child.pid ?? null,
          exitCode: code ?? (timedOut ? 124 : 1),
          signal,
          timedOut,
          durationMs: Date.now() - startedAt,
          error: timedOut ? `Process timed out after ${effectiveTimeoutMs}ms` : null,
          stdoutTail,
          stderrTail,
          logPath: logPath ?? null,
        });
      });

      if (child.stdin) {
        // Guard against EPIPE / ENOENT if the child exits before reading stdin.
        child.stdin.on('error', () => {});
        if (promptDelivery === 'stdin') {
          child.stdin.write(prompt);
        }
        child.stdin.end();
      }
    });
  } finally {
    if (tempPromptFile) {
      await fsp.rm(tempPromptFile, { force: true }).catch(() => {});
    }
  }
}

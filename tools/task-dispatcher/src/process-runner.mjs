import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn, execFile } from 'node:child_process';

/**
 * Kill a process and its entire child process tree on both Windows and POSIX.
 */
export function killProcessTree(child) {
  if (!child || !child.pid) return;
  const pid = child.pid;

  if (process.platform === 'win32') {
    execFile('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, () => {
      // Best-effort cleanup; process may already have exited.
    });
    return;
  }

  try {
    // Detached POSIX children lead their own process group (-pid).
    process.kill(-pid, 'SIGTERM');
  } catch {
    try {
      child.kill('SIGTERM');
    } catch {
      // Already exited.
    }
  }

  setTimeout(() => {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      // Already exited.
    }
  }, 5000).unref();
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
}) {
  let tempPromptFile = null;
  const finalArgs = [...args];

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

      const timer = setTimeout(() => {
        timedOut = true;
        killProcessTree(child);
      }, timeoutMs);

      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
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
        finish({
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
        finish({
          pid: child.pid ?? null,
          exitCode: code ?? (timedOut ? 124 : 1),
          signal,
          timedOut,
          durationMs: Date.now() - startedAt,
          error: timedOut ? `Process timed out after ${timeoutMs}ms` : null,
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

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const ENV_VAR_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/**
 * Recursively expand `${ENV_VAR}` placeholders in string values.
 * Unset env vars expand to an empty string so optional secrets (like webhookUrl)
 * degrade cleanly without throwing.
 */
export function expandEnvVars(value, env = process.env) {
  if (typeof value === 'string') {
    return value.replace(ENV_VAR_PATTERN, (_, name) => env[name] ?? '');
  }
  if (Array.isArray(value)) {
    return value.map((item) => expandEnvVars(item, env));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = expandEnvVars(v, env);
    }
    return out;
  }
  return value;
}

function resolveMaybeRelative(baseDir, targetPath) {
  if (!targetPath) return baseDir;
  if (targetPath.startsWith('~/') || targetPath.startsWith('~\\')) {
    return path.join(os.homedir(), targetPath.slice(2));
  }
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(baseDir, targetPath);
}

/**
 * Load, normalize, and validate a dispatcher configuration file.
 */
export async function loadConfig(configPath, env = process.env) {
  const absConfigPath = path.resolve(configPath);
  const configDir = path.dirname(absConfigPath);
  const rawText = await fs.readFile(absConfigPath, 'utf8');
  const parsed = expandEnvVars(JSON.parse(rawText), env);

  if (!parsed.palace || typeof parsed.palace.baseUrl !== 'string' || !parsed.palace.baseUrl.trim()) {
    throw new Error('Config error: palace.baseUrl is required (e.g. "http://127.0.0.1:8765").');
  }

  const claimMode = parsed.limits?.claimMode ?? 'agent';
  if (claimMode !== 'agent' && claimMode !== 'dispatcher') {
    throw new Error(`Config error: limits.claimMode must be "agent" or "dispatcher", got "${claimMode}".`);
  }

  const harnesses = {};
  for (const [name, cfg] of Object.entries(parsed.harnesses ?? {})) {
    if (!cfg || typeof cfg !== 'object') continue;
    harnesses[name] = {
      name,
      enabled: Boolean(cfg.enabled),
      type: cfg.type ?? name,
      command: cfg.command ?? name,
      args: Array.isArray(cfg.args) ? cfg.args : [],
      extraArgs: Array.isArray(cfg.extraArgs) ? cfg.extraArgs : [],
      attachUrl: typeof cfg.attachUrl === 'string' ? cfg.attachUrl.trim() : '',
      promptDelivery: cfg.promptDelivery ?? 'stdin',
      maxConcurrent: Math.max(1, Number(cfg.maxConcurrent ?? 1)),
      timeoutMs: cfg.timeoutMs ? Number(cfg.timeoutMs) : undefined,
      env: cfg.env && typeof cfg.env === 'object' ? cfg.env : {},
    };
  }

  const repos = {};
  for (const [logicalName, repoPath] of Object.entries(parsed.repos ?? {})) {
    if (typeof repoPath === 'string' && repoPath.trim()) {
      repos[logicalName.toLowerCase()] = resolveMaybeRelative(configDir, repoPath.trim());
    }
  }

  return {
    configPath: absConfigPath,
    executorId: (parsed.executorId || os.hostname()).trim(),
    palace: {
      baseUrl: parsed.palace.baseUrl.replace(/\/+$/, ''),
      token: (parsed.palace.token || '').trim(),
      requestTimeoutMs: Math.max(1000, Number(parsed.palace.requestTimeoutMs ?? 15000)),
      autoStart: {
        enabled: parsed.palace.autoStart?.enabled !== false,
        command: (parsed.palace.autoStart?.command || '').trim(),
        palacePath: parsed.palace.autoStart?.palacePath
          ? resolveMaybeRelative(configDir, parsed.palace.autoStart.palacePath.trim())
          : '',
        tokenFile: parsed.palace.autoStart?.tokenFile
          ? resolveMaybeRelative(configDir, parsed.palace.autoStart.tokenFile.trim())
          : '',
        startupTimeoutMs: Math.max(2000, Number(parsed.palace.autoStart?.startupTimeoutMs ?? 120000)),
        keepAlive: Boolean(parsed.palace.autoStart?.keepAlive),
        extraArgs: Array.isArray(parsed.palace.autoStart?.extraArgs) ? parsed.palace.autoStart.extraArgs : [],
        env: parsed.palace.autoStart?.env && typeof parsed.palace.autoStart.env === 'object'
          ? parsed.palace.autoStart.env
          : {},
      },
    },
    polling: {
      intervalMs: Math.max(1000, Number(parsed.polling?.intervalMs ?? 15000)),
      wings: Array.isArray(parsed.polling?.wings) ? parsed.polling.wings.filter(Boolean) : [],
      watchInbox: parsed.polling?.watchInbox !== false,
      watchPendingTasks: parsed.polling?.watchPendingTasks !== false,
    },
    limits: {
      maxConcurrent: Math.max(1, Number(parsed.limits?.maxConcurrent ?? 2)),
      defaultMaxRounds: Math.max(1, Number(parsed.limits?.defaultMaxRounds ?? 5)),
      defaultTimeoutMs: Math.max(10000, Number(parsed.limits?.defaultTimeoutMs ?? 1800000)),
      claimMode,
      leaseSeconds: Math.max(60, Number(parsed.limits?.leaseSeconds ?? 600)),
    },
    paths: {
      worktreeRoot: resolveMaybeRelative(configDir, parsed.paths?.worktreeRoot ?? './.dispatcher-worktrees'),
      logDir: resolveMaybeRelative(configDir, parsed.paths?.logDir ?? './.dispatcher-logs'),
      stateFile: resolveMaybeRelative(configDir, parsed.paths?.stateFile ?? './.dispatcher-state.json'),
    },
    repos,
    harnesses,
    notifications: {
      webhookUrl: (parsed.notifications?.webhookUrl || '').trim(),
    },
  };
}

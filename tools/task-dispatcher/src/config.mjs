import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const ENV_VAR_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** Maximum safe 32-bit signed timeout accepted by Node's `setTimeout`. */
export const MAX_TIMEOUT_MS = 2_147_483_647;

const VALID_MODES = new Set(['read_only', 'worktree_branch', 'draft_pr']);

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
 * Parse a required/optional numeric config field strictly (rejecting non-finite
 * values or strings like `"two"` that would otherwise coerce to `NaN`) and clamp
 * to `[min, max]`.
 */
export function parseBoundedInt(raw, { name, defaultValue, min, max = Number.MAX_SAFE_INTEGER }) {
  if (raw === undefined || raw === null) {
    return defaultValue;
  }
  if (typeof raw !== 'number' || !Number.isFinite(raw)) {
    throw new Error(`Config error: ${name} must be a finite number, got ${JSON.stringify(raw)}.`);
  }
  return Math.min(max, Math.max(min, Math.floor(raw)));
}

function parseModeList(raw, { name, defaultValue }) {
  if (raw === undefined || raw === null) {
    return [...defaultValue];
  }
  if (!Array.isArray(raw)) {
    throw new Error(`Config error: ${name} must be an array of mode strings.`);
  }
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string' || !VALID_MODES.has(item)) {
      throw new Error(`Config error: ${name} contains invalid mode ${JSON.stringify(item)}.`);
    }
    if (!out.includes(item)) out.push(item);
  }
  return out;
}

function parseBranchPrefix(raw, { name, defaultValue }) {
  if (raw === undefined || raw === null) {
    return defaultValue;
  }
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error(`Config error: ${name} must be a non-empty git branch prefix (e.g. "agent/").`);
  }
  let prefix = raw.trim();
  if (prefix.startsWith('-') || prefix.startsWith('/') || prefix.includes('..') || prefix.includes('@{')) {
    throw new Error(`Config error: ${name} "${prefix}" is not a safe git branch prefix.`);
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(prefix)) {
    throw new Error(`Config error: ${name} "${prefix}" contains unsupported characters.`);
  }
  if (!prefix.endsWith('/')) {
    prefix += '/';
  }
  return prefix;
}

function parseStringList(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => (typeof item === 'string' ? item.trim().toLowerCase() : ''))
    .filter(Boolean);
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
    throw new Error('Config error: palace.baseUrl is required (e.g. "http://127.0.0.1:8775").');
  }

  const claimMode = parsed.limits?.claimMode ?? 'agent';
  if (claimMode !== 'agent' && claimMode !== 'dispatcher') {
    throw new Error(`Config error: limits.claimMode must be "agent" or "dispatcher", got "${claimMode}".`);
  }

  const dispatcherSuccessState = parsed.limits?.dispatcherSuccessState ?? 'input_required';
  if (dispatcherSuccessState !== 'input_required' && dispatcherSuccessState !== 'completed') {
    throw new Error(
      `Config error: limits.dispatcherSuccessState must be "input_required" or "completed", got "${dispatcherSuccessState}".`,
    );
  }

  const defaultMaxRounds = parseBoundedInt(parsed.limits?.defaultMaxRounds, {
    name: 'limits.defaultMaxRounds',
    defaultValue: 5,
    min: 1,
    max: 1000,
  });
  const maxRoundsCap = Math.max(
    defaultMaxRounds,
    parseBoundedInt(parsed.limits?.maxRoundsCap, {
      name: 'limits.maxRoundsCap',
      defaultValue: defaultMaxRounds,
      min: 1,
      max: 1000,
    }),
  );

  const defaultTimeoutMs = parseBoundedInt(parsed.limits?.defaultTimeoutMs, {
    name: 'limits.defaultTimeoutMs',
    defaultValue: 1800000,
    min: 10000,
    max: MAX_TIMEOUT_MS,
  });
  const maxTimeoutMs = Math.max(
    defaultTimeoutMs,
    parseBoundedInt(parsed.limits?.maxTimeoutMs, {
      name: 'limits.maxTimeoutMs',
      defaultValue: defaultTimeoutMs,
      min: 10000,
      max: MAX_TIMEOUT_MS,
    }),
  );

  const policy = {
    allowedCreators: parseStringList(parsed.policy?.allowedCreators),
    allowedSenders: parseStringList(parsed.policy?.allowedSenders),
    allowedModes: parseModeList(parsed.policy?.allowedModes, {
      name: 'policy.allowedModes',
      defaultValue: ['read_only', 'worktree_branch'],
    }),
    allowCommit: Boolean(parsed.policy?.allowCommit),
    allowPush: Boolean(parsed.policy?.allowPush),
    branchPrefix: parseBranchPrefix(parsed.policy?.branchPrefix, {
      name: 'policy.branchPrefix',
      defaultValue: 'agent/',
    }),
  };

  const harnesses = {};
  for (const [name, cfg] of Object.entries(parsed.harnesses ?? {})) {
    if (!cfg || typeof cfg !== 'object') continue;
    const key = name.trim().toLowerCase();
    harnesses[key] = {
      name: key,
      enabled: Boolean(cfg.enabled),
      type: cfg.type ?? key,
      command: cfg.command ?? key,
      args: Array.isArray(cfg.args) ? cfg.args : [],
      extraArgs: Array.isArray(cfg.extraArgs) ? cfg.extraArgs : [],
      attachUrl: typeof cfg.attachUrl === 'string' ? cfg.attachUrl.trim() : '',
      promptDelivery: cfg.promptDelivery ?? 'stdin',
      maxConcurrent: parseBoundedInt(cfg.maxConcurrent, {
        name: `harnesses.${name}.maxConcurrent`,
        defaultValue: 1,
        min: 1,
        max: 32,
      }),
      timeoutMs:
        cfg.timeoutMs !== undefined && cfg.timeoutMs !== null
          ? parseBoundedInt(cfg.timeoutMs, {
              name: `harnesses.${name}.timeoutMs`,
              defaultValue: defaultTimeoutMs,
              min: 10000,
              max: MAX_TIMEOUT_MS,
            })
          : undefined,
      actorAliases: parseStringList(cfg.actorAliases),
      env: cfg.env && typeof cfg.env === 'object' ? cfg.env : {},
    };
  }

  const repos = {};
  for (const [logicalName, entry] of Object.entries(parsed.repos ?? {})) {
    const key = logicalName.trim().toLowerCase();
    if (typeof entry === 'string' && entry.trim()) {
      repos[key] = {
        path: resolveMaybeRelative(configDir, entry.trim()),
        allowedModes: [...policy.allowedModes],
        allowCommit: policy.allowCommit,
        allowPush: policy.allowPush,
        branchPrefix: policy.branchPrefix,
      };
    } else if (entry && typeof entry === 'object' && typeof entry.path === 'string' && entry.path.trim()) {
      repos[key] = {
        path: resolveMaybeRelative(configDir, entry.path.trim()),
        allowedModes: parseModeList(entry.allowedModes, {
          name: `repos.${logicalName}.allowedModes`,
          defaultValue: policy.allowedModes,
        }),
        allowCommit: entry.allowCommit !== undefined ? Boolean(entry.allowCommit) : policy.allowCommit,
        allowPush: entry.allowPush !== undefined ? Boolean(entry.allowPush) : policy.allowPush,
        branchPrefix: parseBranchPrefix(entry.branchPrefix, {
          name: `repos.${logicalName}.branchPrefix`,
          defaultValue: policy.branchPrefix,
        }),
      };
    }
  }

  return {
    configPath: absConfigPath,
    executorId: (parsed.executorId || os.hostname()).trim(),
    palace: {
      baseUrl: parsed.palace.baseUrl.replace(/\/+$/, ''),
      token: (parsed.palace.token || '').trim(),
      tokenIdentity: (parsed.palace.tokenIdentity || '').trim().toLowerCase(),
      requestTimeoutMs: parseBoundedInt(parsed.palace.requestTimeoutMs, {
        name: 'palace.requestTimeoutMs',
        defaultValue: 15000,
        min: 1000,
        max: MAX_TIMEOUT_MS,
      }),
      autoStart: {
        // Explicit opt-in only: never hijack a loopback port meant for an SSH/federation tunnel.
        enabled: Boolean(parsed.palace.autoStart?.enabled),
        command: (parsed.palace.autoStart?.command || '').trim(),
        palacePath: parsed.palace.autoStart?.palacePath
          ? resolveMaybeRelative(configDir, parsed.palace.autoStart.palacePath.trim())
          : '',
        tokenFile: parsed.palace.autoStart?.tokenFile
          ? resolveMaybeRelative(configDir, parsed.palace.autoStart.tokenFile.trim())
          : '',
        startupTimeoutMs: parseBoundedInt(parsed.palace.autoStart?.startupTimeoutMs, {
          name: 'palace.autoStart.startupTimeoutMs',
          defaultValue: 120000,
          min: 2000,
          max: MAX_TIMEOUT_MS,
        }),
        keepAlive: Boolean(parsed.palace.autoStart?.keepAlive),
        extraArgs: Array.isArray(parsed.palace.autoStart?.extraArgs) ? parsed.palace.autoStart.extraArgs : [],
        env:
          parsed.palace.autoStart?.env && typeof parsed.palace.autoStart.env === 'object'
            ? parsed.palace.autoStart.env
            : {},
      },
    },
    polling: {
      intervalMs: parseBoundedInt(parsed.polling?.intervalMs, {
        name: 'polling.intervalMs',
        defaultValue: 15000,
        min: 1000,
        max: MAX_TIMEOUT_MS,
      }),
      wings: Array.isArray(parsed.polling?.wings)
        ? parsed.polling.wings.map((w) => (typeof w === 'string' ? w.trim() : '')).filter(Boolean)
        : [],
      watchInbox: parsed.polling?.watchInbox !== false,
      watchPendingTasks: parsed.polling?.watchPendingTasks !== false,
    },
    limits: {
      maxConcurrent: parseBoundedInt(parsed.limits?.maxConcurrent, {
        name: 'limits.maxConcurrent',
        defaultValue: 2,
        min: 1,
        max: 64,
      }),
      defaultMaxRounds,
      maxRoundsCap,
      defaultTimeoutMs,
      maxTimeoutMs,
      claimMode,
      dispatcherSuccessState,
      leaseSeconds: parseBoundedInt(parsed.limits?.leaseSeconds, {
        name: 'limits.leaseSeconds',
        defaultValue: 600,
        min: 60,
        max: 86400,
      }),
      maxSeenMessages: parseBoundedInt(parsed.limits?.maxSeenMessages, {
        name: 'limits.maxSeenMessages',
        defaultValue: 5000,
        min: 100,
        max: 100000,
      }),
    },
    policy,
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

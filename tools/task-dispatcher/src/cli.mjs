#!/usr/bin/env node
import path from 'node:path';
import { loadConfig } from './config.mjs';
import { PalaceClient } from './palace-client.mjs';
import { ensurePalaceServer } from './palace-launcher.mjs';
import { TaskDispatcher } from './dispatcher.mjs';

function parseArgs(argv) {
  const opts = {
    config: './dispatcher.config.json',
    once: false,
    dryRun: false,
    noAutoStart: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      opts.help = true;
    } else if (arg === '--once') {
      opts.once = true;
    } else if (arg === '--dry-run') {
      opts.dryRun = true;
    } else if (arg === '--no-auto-start') {
      opts.noAutoStart = true;
    } else if (arg === '--config' || arg === '-c') {
      opts.config = argv[++i];
    } else if (arg.startsWith('--config=')) {
      opts.config = arg.slice('--config='.length);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`Usage: agentpalace-dispatcher [options]

Cross-platform (Windows & Linux) zero-token AgentPalace task & inbox dispatcher.

Options:
  -c, --config <path>   Path to JSON config file (default: ./dispatcher.config.json)
      --once            Run a single poll cycle, wait for launched runs, then exit
      --dry-run         Log what would be dispatched without spawning harnesses
      --no-auto-start   Do not automatically launch \`agentpalace serve\` if unreachable
  -h, --help            Show this help message
`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return;
  }

  const config = await loadConfig(path.resolve(opts.config));
  if (opts.noAutoStart) {
    config.palace.autoStart.enabled = false;
  }

  const client = new PalaceClient(config.palace);
  const palaceHandle = await ensurePalaceServer({ config, client });

  const dispatcher = new TaskDispatcher({
    config,
    client,
    dryRun: opts.dryRun,
  });

  if (opts.once) {
    try {
      await dispatcher.loadState();
      const launched = await dispatcher.pollOnce();
      await dispatcher.waitForInflight();
      console.log(`[dispatcher] Completed --once cycle (${launched.length} dispatched).`);
    } finally {
      await palaceHandle.stop();
    }
    return;
  }

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[dispatcher] Received ${signal}; waiting for active runs to finish...`);
    await dispatcher.stop();
    await palaceHandle.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  await dispatcher.start();
}

main().catch((err) => {
  console.error(`[dispatcher] Fatal error: ${err.message}`);
  process.exit(1);
});

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
    autoStart: undefined,
    resetTask: null,
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
    } else if (arg === '--auto-start') {
      opts.autoStart = true;
    } else if (arg === '--no-auto-start') {
      opts.autoStart = false;
    } else if (arg === '--reset-task') {
      if (i + 1 >= argv.length) throw new Error('Missing value for --reset-task');
      opts.resetTask = argv[++i];
    } else if (arg.startsWith('--reset-task=')) {
      opts.resetTask = arg.slice('--reset-task='.length);
    } else if (arg === '--config' || arg === '-c') {
      if (i + 1 >= argv.length) throw new Error('Missing value for --config');
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
  -c, --config <path>       Path to JSON config file (default: ./dispatcher.config.json)
      --once                Run a single poll cycle, wait for launched runs, then exit
      --dry-run             Log what would be dispatched without spawning harnesses
      --auto-start          Enable auto-launching \`agentpalace serve\` on loopback if unreachable
      --no-auto-start       Disable auto-launching \`agentpalace serve\`
      --reset-task <id>     Clear persisted round count and cap notice for <id> and exit
  -h, --help                Show this help message
`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return;
  }

  const config = await loadConfig(path.resolve(opts.config));
  if (opts.autoStart !== undefined) {
    config.palace.autoStart.enabled = opts.autoStart;
  }

  const client = new PalaceClient(config.palace);
  let palaceHandle = null;
  const dispatcher = new TaskDispatcher({
    config,
    client,
    dryRun: opts.dryRun,
  });

  if (opts.resetTask) {
    await dispatcher.resetTask(opts.resetTask);
    console.log(`[dispatcher] Cleared round cap state for ${opts.resetTask}.`);
    return;
  }

  try {
    palaceHandle = await ensurePalaceServer({ config, client });

    if (opts.once) {
      await dispatcher.loadState();
      const launched = await dispatcher.pollOnce();
      await dispatcher.waitForInflight();
      console.log(`[dispatcher] Completed --once cycle (${launched.length} dispatched).`);
      return;
    }

    let shuttingDown = false;
    const shutdown = async (signal) => {
      if (shuttingDown) {
        console.error(`\n[dispatcher] Second ${signal} received; terminating active processes and exiting...`);
        await Promise.race([
          Promise.allSettled([dispatcher.forceStop(), palaceHandle?.stop()]),
          new Promise((r) => setTimeout(r, 4000)),
        ]);
        process.exit(130);
      }
      shuttingDown = true;
      console.log(
        `\n[dispatcher] Received ${signal}; waiting for active runs to finish (press Ctrl-C again to force exit)...`,
      );
      await dispatcher.stop();
      await palaceHandle?.stop();
      process.exit(0);
    };

    process.on('SIGINT', () => void shutdown('SIGINT'));
    process.on('SIGTERM', () => void shutdown('SIGTERM'));

    await dispatcher.start();
  } catch (err) {
    await dispatcher.forceStop().catch(() => {});
    await palaceHandle?.stop().catch(() => {});
    throw err;
  } finally {
    if (opts.once && palaceHandle) {
      await palaceHandle.stop().catch(() => {});
    }
  }
}

main().catch((err) => {
  console.error(`[dispatcher] Fatal error: ${err.message}`);
  process.exit(1);
});

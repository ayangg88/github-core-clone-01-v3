// Boot and lifecycle for the forge entry.
//
// The harness (the "env") starts beside this process and tells us where it
// lives through MAKEFUN_ENV_URL. We pick a free port, tell the env about it,
// then keep asking the env whether the trial is finished. When it says done
// we shut the server down and leave with status 0. Nothing here does any
// forge work itself; that all lives in app.ts.

import { createApp } from './app.ts';

const envBase = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envBase === '') {
  process.stderr.write('[forge] MAKEFUN_ENV_URL is not set, so there is no env to join\n');
  process.exit(1);
}

const CALL_BUDGET_MS = 30_000;
const FIRST_PAUSE_MS = 250;
const LONGEST_PAUSE_MS = 2_000;

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Backoff between retries: double from FIRST_PAUSE_MS up to LONGEST_PAUSE_MS.
function pauseFor(failures: number): number {
  const doubled = FIRST_PAUSE_MS * 2 ** Math.min(failures, 8);
  return Math.min(LONGEST_PAUSE_MS, doubled);
}

// Tell the env which port we bound. A 200 means it heard us; a 409 means
// another entry registered first and this one simply waits along. A 400 or
// 405 is a contract mistake and ends the process; anything else (including a
// network error, while the env is still starting) is retried.
async function announce(port: number): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const answer = await fetch(`${envBase}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(CALL_BUDGET_MS),
      });
      if (answer.status === 200 || answer.status === 409) return;
      if (answer.status === 400 || answer.status === 405) {
        throw new Error(`register refused with HTTP ${answer.status}: ${await answer.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register refused with HTTP ')) throw err;
    }
    await pause(pauseFor(failures));
  }
}

// Ask the env, over and over, whether the trial is over. The env answers
// immediately either way, so this is a poll; a slow or failed poll just
// means "not yet" and we try again a little later.
async function waitUntilDone(): Promise<void> {
  for (let failures = 0; ; failures += 1) {
    try {
      const answer = await fetch(`${envBase}/done`, { signal: AbortSignal.timeout(CALL_BUDGET_MS) });
      if (answer.ok) {
        const body = (await answer.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // No answer yet: the trial is still running.
    }
    await pause(pauseFor(failures));
  }
}

async function boot(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve) => {
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    process.stderr.write('[forge] the server bound no port\n');
    process.exit(1);
  }
  await announce(address.port);
  await waitUntilDone();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

boot().catch((err: unknown) => {
  process.stderr.write(`[forge] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});

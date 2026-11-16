#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const suites = ['test-core.mjs', 'test-policy.mjs', 'test-file.mjs', 'test-harness.mjs', 'test-room.mjs', 'test-signal.mjs', 'test-media.mjs', 'test-vectors.mjs', 'test-fuzz.mjs', 'test-http.mjs', 'test-auth.mjs'];
let failed = 0;

for (const suite of suites) {
  console.log(`\n== ${suite}`);
  const result = spawnSync(process.execPath, [join(dir, suite)], { stdio: 'inherit' });
  if ((result.status ?? 1) !== 0) failed++;
}

process.exit(failed ? 1 : 0);

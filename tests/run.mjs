#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const suites = ['test-core.mjs', 'test-http.mjs'];
let failed = 0;

for (const suite of suites) {
  console.log(`\n== ${suite}`);
  const result = spawnSync(process.execPath, [join(dir, suite)], { stdio: 'inherit' });
  if ((result.status ?? 1) !== 0) failed++;
}

process.exit(failed ? 1 : 0);

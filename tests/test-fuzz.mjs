#!/usr/bin/env node
import { requireExe, run } from './commons.mjs';

requireExe();
let failed = 0;

function check(condition, label, detail = '') {
  if (condition) {
    console.log(`  ok  ${label}`);
  } else {
    console.error(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

const fuzz = run(['fuzz']);
check(fuzz.status === 0, 'fuzz exits 0', fuzz.stdout || fuzz.stderr);
check(fuzz.json?.schema === 'pm.encryption.fuzz.v1', 'fuzz schema');
check(fuzz.json?.ok === true, 'fuzz accepted no mutated input', fuzz.stdout);
check(fuzz.json?.accepted === 0, 'accepted count stays at zero');
check(fuzz.json?.trials >= 100, 'fuzz covers more than a handful of mutations', fuzz.stdout);
check(fuzz.json?.handshake === true && fuzz.json?.frame === true && fuzz.json?.file === true,
  'handshake, frame, and file parsers are in the run');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

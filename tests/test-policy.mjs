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

const capabilities = run(['capabilities']);
check(capabilities.status === 0, 'capabilities exits 0', capabilities.stderr);
check(capabilities.json?.policies?.live_session === true, 'live session policy is enabled');
check(capabilities.json?.policies?.signal === false, 'signal session policy stays disabled');
check(capabilities.json?.policies?.mls === false, 'mls session policy stays disabled');

const list = run(['policy', 'list']);
check(list.status === 0 && list.json?.schema === 'pm.encryption.policy.v1',
  'policy list exits 0', list.stdout || list.stderr);
const listed = new Map((list.json?.policies || []).map((row) => [row.id, row]));
check(listed.get('live_session')?.enabled === true && listed.get('live_session')?.level === 'low',
  'live session is listed as the low-level policy');
check(listed.get('signal')?.enabled === false && listed.get('signal')?.level === 'session',
  'signal is listed as a disabled session policy');

const live = run(['policy', 'live']);
check(live.status === 0, 'live policy suite exits 0', live.stdout || live.stderr);
check(live.json?.schema === 'pm.encryption.policy.v1' && live.json?.policy === 'live_session',
  'live policy result names itself');
check(live.json?.ok === true && live.json?.failed === 0 && live.json?.passed >= 8,
  'live policy isolated checks pass', live.stdout);
check(!live.stdout.includes('http://'), 'live policy suite does not open the chat harness');

const signal = run(['policy', 'signal']);
check(signal.status === 1 && signal.json?.code === 'feature_disabled',
  'signal policy refuses while its feature is off', signal.stdout || signal.stderr);

const unknown = run(['policy', 'unknown']);
check(unknown.status === 1 && unknown.json?.code === 'unknown_policy',
  'unknown policy is a typed failure', unknown.stdout);

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

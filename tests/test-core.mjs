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
check(capabilities.json?.schema === 'pm.encryption.capabilities.v1', 'capabilities schema');
check(capabilities.json?.secure_channel_e2ee === true, 'generic secure channel is compiled');
check(capabilities.json?.chat_http_sse_harness === true, 'chat HTTP/SSE vertical is compiled');
check(capabilities.json?.libsignal === false, 'libsignal is not silently enabled');

const selftest = run(['selftest']);
check(selftest.status === 0, 'selftest exits 0', selftest.stdout || selftest.stderr);
check(selftest.json?.schema === 'pm.encryption.selftest.v1', 'selftest schema');
check(selftest.json?.ok === true && selftest.json?.failed === 0, 'all native checks pass',
  selftest.stdout);
check(selftest.json?.passed >= 14, 'native suite covers adversarial cases', selftest.stdout);

const scenario = run(['scenario', 'tanit-chat-wifi']);
check(scenario.status === 0 && scenario.json?.ok === true, 'Wi-Fi chat scenario passes',
  scenario.stdout || scenario.stderr);

const roundtrip = run(['roundtrip', '--text', 'hello over wifi']);
check(roundtrip.status === 0, 'roundtrip exits 0', roundtrip.stdout || roundtrip.stderr);
check(roundtrip.json?.match === true, 'roundtrip recovered exact bytes');
check(roundtrip.json?.frame_bytes > roundtrip.json?.plaintext_bytes, 'ciphertext has framed overhead');
check(roundtrip.json?.plaintext === undefined, 'CLI does not echo plaintext');

const unknown = run(['scenario', 'unknown']);
check(unknown.status === 1 && unknown.json?.code === 'unknown_scenario',
  'unknown scenario is a typed failure', unknown.stdout);

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

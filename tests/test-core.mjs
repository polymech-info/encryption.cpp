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
check(capabilities.json?.libsignal === true, 'libsignal adapter is compiled in the dev build');
check(capabilities.json?.policies?.live_session === true, 'live session policy is enabled');
check(capabilities.json?.policies?.signal === true, 'signal session policy is enabled');
check(capabilities.json?.authenticated_handshake === true, 'authenticated handshake is compiled');
check(capabilities.json?.handshake === 'sigma-i-v1', 'handshake profile is sigma-i-v1');
check(capabilities.json?.ratchet === false, 'the live channel does not ratchet');
check(capabilities.json?.history === 'out-of-channel', 'history stays outside this channel');
check(capabilities.json?.replay_rule === 'sequence-0-then-window-64',
  'replay starts at sequence 0');
check(capabilities.json?.features?.unauthenticated_kx === true,
  'unauthenticated exchange is an explicit feature flag');
check(capabilities.json?.features?.libsignal === true, 'libsignal CMake feature is on');
check(capabilities.json?.features?.http_harness === true, 'HTTP harness CMake feature is on');

const seed = '11'.repeat(32);
const identity = run(['identity', '--seed', seed]);
const identityAgain = run(['identity', '--seed', seed]);
const otherIdentity = run(['identity', '--seed', '22'.repeat(32)]);
check(identity.status === 0 && identity.json?.schema === 'pm.encryption.identity.v1',
  'identity command exits 0', identity.stdout || identity.stderr);
check(identity.json?.public_key && identity.json.public_key === identityAgain.json?.public_key,
  'identity seed is deterministic');
check(identity.json?.public_key !== otherIdentity.json?.public_key,
  'distinct seeds produce distinct identity keys');
check(!identity.stdout.includes(seed), 'identity output does not echo the seed');

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

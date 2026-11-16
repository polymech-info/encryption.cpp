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
check(capabilities.json?.handshake_property === 'pinned-online',
  'capabilities name the pinned handshake');
check(capabilities.json?.identity_hiding === false, 'capabilities do not claim identity hiding');
check(capabilities.json?.channel_key === 'one-for-process',
  'capabilities state one channel key for the process');
check(capabilities.json?.broker === false, 'capabilities state that there is no broker');
check(capabilities.json?.handshake === 'sigma-i-v1', 'wire label is unchanged');

const open = run(['chat-harness', '--host', '0.0.0.0']);
check(open.status === 2 && open.json?.code === 'not_loopback',
  'a public host is refused', open.stdout || open.stderr);

const harness = run(['chat-harness', '--text', 'desk-hello']);
check(harness.status === 0, 'desktop chat harness exits 0', harness.stdout || harness.stderr);
check(harness.json?.schema === 'pm.encryption.chat-harness.v1', 'harness schema');
check(harness.json?.host === '127.0.0.1' && harness.json?.loopback === true, 'harness bound loopback');
check(harness.json?.broker === false, 'harness has no broker');
check(harness.json?.pinned === true && harness.json?.identity_hiding === false,
  'both peers are pinned and identities are not hidden');
check(harness.json?.handshake === 'pinned-online' && harness.json?.wire_label === 'sigma-i-v1',
  'harness names the property and the wire label separately');
check(harness.json?.channel_key === 'one-for-process', 'one channel key is part of the result');
check(harness.json?.files === false, 'the chat harness does not seal files');
check(harness.json?.frame_context === 'transcript-hash', 'frame context is the transcript hash');
check(harness.json?.frame_cap_bytes === 16384, 'frame cap is 16 KiB');
check(harness.json?.unauthenticated_rejected === true, 'unauthenticated exchange is rejected');
check(harness.json?.chat_before_handshake_rejected === true,
  'chat before message 3 is rejected');
check(harness.json?.both_complete_before_chat === true && harness.json?.reply_matches === true,
  'chat bytes move only after both sides finish');
check(!harness.stdout.includes('desk-hello'), 'stdout does not contain the chat text');

const oversize = run(['chat-harness', '--text', 'x'.repeat(16385)]);
check(oversize.status === 1 && oversize.json?.code === 'plaintext_too_large',
  'a frame over 16 KiB is refused before bind', oversize.stdout || oversize.stderr);

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

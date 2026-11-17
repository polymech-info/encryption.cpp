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

const flow = run(['flow']);
check(flow.status === 0, 'flow exits 0', flow.stdout || flow.stderr);
check(flow.json?.schema === 'pm.encryption.flow.v1', 'flow schema');
check(flow.json?.ok === true, 'flow checks pass', flow.stdout);
check(flow.json?.delivery === 'datagram', 'the facade opens a datagram flow');
check(flow.json?.chat_bytes === true, 'chat bytes seal and open');
check(flow.json?.binary === true, 'arbitrary binary seals and opens');
check(flow.json?.encoded_frame === true, 'an encoded-looking frame seals and opens');
check(flow.json?.flow_separated === true, 'one flow cannot open another flow');
check(flow.json?.scope_separated === true, 'a different scope cannot open the frame');
check(flow.json?.epoch_separated === true, 'a new epoch cannot open the previous epoch');
check(flow.json?.old_key_kept === true, 'a peer who kept the old key still opens it');
check(flow.json?.close_local_only === true, 'close wipes the local flow only');
check(flow.json?.gap === true, 'a later datagram opens before an earlier one');
check(flow.json?.replay_rejected === true, 'a repeated datagram sequence is rejected');
check(flow.json?.reliable_rejected === true, 'reliable delivery is refused by this facade');
check(flow.json?.durable_rejected === true, 'durable delivery is refused by this facade');
check(flow.json?.size_rejected === true, 'a datagram over 64 KiB is refused');
check(flow.json?.receiver_cannot_send === true, 'a receiver cannot seal with the sender key');
check(flow.json?.receiver_cannot_rekey === true, 'a receiver cannot advance the epoch');
check(flow.json?.stale_wrap_rejected === true, 'a receiver rejects a wrap that is not newer');
check(flow.json?.webrtc === false && flow.json?.transport === false, 'no socket or webrtc is opened');
check(!flow.stdout.includes('flow-'), 'stdout does not contain the flow payloads');
check(!flow.stdout.includes('PMD1-looking-frame'), 'stdout does not contain the encoded payload');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

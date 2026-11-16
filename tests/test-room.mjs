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
check(capabilities.json?.room_broker === 'in-process-v1', 'room broker contract is compiled');
check(capabilities.json?.pairing === 'fingerprint-v1', 'pairing is the fingerprint exchange');
check(capabilities.json?.tailnet === false, 'a tailnet is not treated as a user identity');
check(capabilities.json?.broker === false, 'no network broker is deployed');

const room = run(['room-harness', '--text', 'room-hello']);
check(room.status === 0, 'room harness exits 0', room.stdout || room.stderr);
check(room.json?.schema === 'pm.room.harness.v1', 'room harness schema');
check(room.json?.underlay === 'loopback' && room.json?.tailnet === false, 'relay stays on loopback');
check(room.json?.tailnet_authenticates_users === false, 'tailnet authentication is not user pairing');
check(room.json?.pairing === 'fingerprint-v1', 'devices pair by comparing fingerprints');
check(room.json?.fingerprint_mismatch_rejected === true, 'a wrong fingerprint is rejected');
check(room.json?.substituted_offer_rejected === true, 'a swapped initiator key is rejected');
check(room.json?.members === 2 && room.json?.grants === 'chat', 'the room has the two paired devices');
check(room.json?.audio === false && room.json?.video === false && room.json?.files === false,
  'this chat room did not join a media grant');
check(room.json?.files_grant_rejected === true, 'file bytes are not a room grant');
check(room.json?.media_grant_separate === true, 'audio and video are a separate invite');
check(room.json?.invite_reused_rejected === true, 'an invite is single-use');
check(room.json?.outsider_rejected === true, 'an unpaired device cannot post');
check(room.json?.relayed_chat === true && room.json?.broker_sees_plaintext === false,
  'the broker relays ciphertext');
check(room.json?.tamper_rejected === true, 'a flipped relayed frame fails authentication');
check(room.json?.manifest_reference_hidden === true, 'a file reference is not readable at the broker');
check(room.json?.membership_rotates_keys === false, 'membership does not rotate channel keys');
check(room.json?.channel_key === 'one-for-process', 'the live session still has one channel key');
check(!room.stdout.includes('room-hello'), 'stdout does not contain the chat text');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

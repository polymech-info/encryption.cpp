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

const room = run(['signal-room', '--text', 'text-room-secret']);
check(room.status === 0, 'signal room exits 0', room.stdout || room.stderr);
check(room.json?.schema === 'pm.signal.room.v1', 'signal room schema');
check(room.json?.ok === true, 'signal room checks pass', room.stdout);
check(room.json?.policy === 'signal', 'room names the signal policy');
check(room.json?.session === 'pqxdh-triple-ratchet', 'session is upstream PQXDH plus the Triple Ratchet');
check(room.json?.offline_first === true, 'the first message opens from a prekey bundle');
check(room.json?.reply === true, 'the reply advances the ratchet');
check(room.json?.reorder === true, 'a later message can arrive before the previous one');
check(room.json?.no_onetime_prekey === true, 'a bundle without a one-time prekey still opens');
check(room.json?.duplicate_rejected === true, 'a repeated ciphertext is rejected');
check(room.json?.tamper_rejected === true, 'a modified ciphertext is rejected');
check(room.json?.outsider_rejected === true, 'a device outside the session cannot read it');
check(room.json?.files_grant_rejected === true, 'file bytes are not a room grant');
check(room.json?.audio === false && room.json?.video === false, 'the room is text');
check(room.json?.plaintext_hidden === true, 'the broker store does not hold the text');
check(room.json?.members === 2, 'the paired room has two members');
check(!room.stdout.includes('text-room-secret'), 'stdout does not contain the chat text');
check(!room.stdout.includes('no-onetime'), 'stdout does not contain the prekey-less text');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

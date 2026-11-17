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
check(capabilities.json?.text_session === 'pairwise-v1', 'text session is the pairwise chat API');

const live = run(['chat', '--policy', 'live', '--text', 'chat-policy-text']);
check(live.status === 0, 'live chat exits 0', live.stdout || live.stderr);
check(live.json?.schema === 'pm.encryption.chat.v1', 'live chat schema');
check(live.json?.policy === 'live_session', 'live chat names its policy');
check(live.json?.socket === false && live.json?.hosts === 'desktop-android', 'the same API is for desktop and Android');
check(live.json?.peers === 2 && live.json?.members === 3, 'three members are two pairwise sessions');
check(live.json?.shared_key === false && live.json?.pairwise === true, 'a room grant is not a shared chat key');
check(live.json?.relayed === true && live.json?.broker_sees_plaintext === false, 'the broker relays ciphertext');
check(live.json?.other_session_rejected === true, 'another session cannot open the text');
check(live.json?.other_device_rejected === true, 'another device ignores the frame');
check(live.json?.unauthenticated_refused === true, 'chat refuses an unauthenticated channel');
check(live.json?.mls_refused === true, 'chat refuses a group ratchet');
check(live.json?.channel_key === 'one-for-process', 'the live text session has one channel key');
check(!live.stdout.includes('chat-policy-text'), 'stdout does not contain the live text');

const signal = run(['chat', '--policy', 'signal', '--text', 'chat-policy-text']);
check(signal.status === 0, 'signal chat exits 0', signal.stdout || signal.stderr);
check(signal.json?.policy === 'signal' && signal.json?.channel_key === 'ratchet', 'signal chat uses the ratchet');
check(signal.json?.signal_bound_to_device === false, 'a signal name is not the device identity');
check(signal.json?.shared_key === false && signal.json?.peers === 2, 'signal chat stays pairwise');
check(signal.json?.other_session_rejected === true && signal.json?.other_device_rejected === true,
  'signal text does not open on the other session');
check(!signal.stdout.includes('chat-policy-text'), 'stdout does not contain the signal text');

const unauth = run(['chat', '--policy', 'unauthenticated-kx', '--text', 'chat-policy-text']);
check(unauth.status !== 0 && unauth.json?.ok === false, 'the unauthenticated policy is refused');
check(!String(unauth.stdout).includes('chat-policy-text'), 'a refused policy does not print the text');

const mls = run(['chat', '--policy', 'mls', '--text', 'chat-policy-text']);
check(mls.status !== 0 && mls.json?.ok === false, 'the mls policy is refused');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

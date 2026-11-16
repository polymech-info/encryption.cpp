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
check(capabilities.json?.file_transfer === 'sealed-manifest-v1', 'file transfer envelope is compiled');
check(capabilities.json?.features?.vfs === true, 'vfs jail is linked into the file scenario');
check(capabilities.json?.policies?.mls === false, 'MLS is not the group-file mechanism');

const scenario = run(['scenario', 'group-file']);
check(scenario.status === 0, 'group-file scenario exits 0', scenario.stdout || scenario.stderr);
check(scenario.json?.schema === 'pm.encryption.file.v1', 'file scenario schema');
check(scenario.json?.scenario === 'group-file', 'scenario names itself');
check(scenario.json?.group_key === 'per-recipient-seal', 'content key is sealed per recipient');
check(scenario.json?.file_key === 'separate-x25519', 'file keys are separate from the signing identity');
check(scenario.json?.file_key_is_identity === false, 'the signing identity is not the file key');
check(scenario.json?.removal_revokes_old_ciphertext === false,
  'removing a recipient does not revoke an older file');
check(scenario.json?.chunk_reseal === false, 'a chunk index cannot be sealed twice');
check(scenario.json?.staging_deleted === true, 'staging plaintext is deleted after publish');
check(scenario.json?.mls === false, 'scenario does not claim an MLS ratchet');
check(scenario.json?.members === 4 && scenario.json?.recipients === 2,
  'two of four room members can open the file');
check(scenario.json?.chunk_count === 4, 'multi-chunk payload');
check(scenario.json?.shared_mount_holds_ciphertext === true,
  'shared vfs mount holds ciphertext');
check(scenario.json?.outsider_rejected === true, 'a non-recipient is rejected');
check(scenario.json?.resume === true, 'resume publishes only after verification');
check(scenario.json?.ok === true && scenario.json?.failed === 0, 'all file checks pass',
  scenario.stdout);
check(scenario.json?.passed >= 16, 'suite covers the hostile file cases', scenario.stdout);
check(!scenario.stdout.includes('chat-file!'), 'stdout does not contain the plaintext');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
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

const dir = dirname(fileURLToPath(import.meta.url));
const published = JSON.parse(readFileSync(join(dir, 'vectors', 'kat.v1.json'), 'utf8'));
const vectors = run(['vectors']);
check(vectors.status === 0, 'vectors exits 0', vectors.stdout || vectors.stderr);
check(vectors.json?.schema === 'pm.encryption.vectors.v1', 'vector schema');
check(JSON.stringify(vectors.json) === JSON.stringify(published),
  'published handshake, frame, and file bytes are unchanged');
check(typeof vectors.json?.message_1 === 'string' && vectors.json.message_1.length > 0,
  'message 1 is present');
check(typeof vectors.json?.transcript === 'string' && typeof vectors.json?.transcript_hash === 'string',
  'transcript and its hash are present');
check(typeof vectors.json?.frame === 'string' && Array.isArray(vectors.json?.file_chunks),
  'frame and file chunks are present');
check(typeof vectors.json?.datagram_packet === 'string'
  && typeof vectors.json?.datagram_rekey_packet === 'string'
  && vectors.json.datagram_label_a !== vectors.json.datagram_label_b,
  'datagram packets, rekey, and distinct labels are present');
check(!vectors.stdout.includes('BEGIN PRIVATE'), 'vector output is the known-answer record');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

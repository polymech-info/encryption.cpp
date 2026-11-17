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

const host = run(['media-host']);
check(host.status === 0, 'media host exits 0', host.stdout || host.stderr);
check(host.json?.schema === 'pm.host.media.v1', 'media host schema');
check(host.json?.ok === true, 'media host checks pass', host.stdout);
check(host.json?.host === 'in-process', 'the host is the in-package stand-in');
check(host.json?.capture === true && host.json?.render === true, 'capture reaches the other host');
check(host.json?.muted === true, 'a muted microphone is not published');
check(host.json?.grant_required === true, 'chat alone cannot publish a microphone');
check(host.json?.rekey === true, 'a new generation renders on the new key');
check(host.json?.stale_discarded === true, 'a packet from the old generation is discarded');
check(host.json?.media_hidden === true, 'the broker does not hold the captured bytes');
check(host.json?.frames === 4, 'the broker stored the bundle and the key wraps');
check(host.json?.rendered === 4, 'three live frames and the rekeyed frame were rendered');
check(host.json?.codec === false && host.json?.webrtc === false && host.json?.transport === false,
  'the host does not pretend to be a codec or a WebRTC stack');
check(!host.stdout.includes('mic-'), 'stdout does not contain the microphone payload');
check(!host.stdout.includes('cam-'), 'stdout does not contain the camera payload');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

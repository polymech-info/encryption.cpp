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

const room = run(['media-room']);
check(room.status === 0, 'media room exits 0', room.stdout || room.stderr);
check(room.json?.schema === 'pm.media.room.v1', 'media room schema');
check(room.json?.ok === true, 'media room checks pass', room.stdout);
check(room.json?.audio === true && room.json?.video === true, 'audio and video frames open');
check(room.json?.transport === false, 'no media transport is linked');
check(room.json?.gap === true, 'a lost audio frame does not block the next one');
check(room.json?.video_opened === true, 'the video frame opens on its own key');
check(room.json?.replay_rejected === true, 'a repeated media sequence is rejected');
check(room.json?.tamper_rejected === true, 'a modified media frame is rejected');
check(room.json?.kind_separated === true, 'an audio frame does not open as video');
check(room.json?.generation_separated === true, 'a new generation does not open the old frame');
check(room.json?.outsider_rejected === true, 'a different media key cannot open the frame');
check(room.json?.files_grant_rejected === true, 'file bytes are not a room grant');
check(room.json?.media_hidden === true, 'the broker store does not hold the media bytes');
check(room.json?.frames === 3, 'the broker stored the bundle and the two key wraps');
check(room.json?.grants === 'chat+audio+video', 'the room grant covers chat, audio, and video');
check(!room.stdout.includes('audio-frame-'), 'stdout does not contain the audio payload');
check(!room.stdout.includes('video-frame-'), 'stdout does not contain the video payload');

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

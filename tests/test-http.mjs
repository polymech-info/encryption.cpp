#!/usr/bin/env node
import { request } from 'node:http';
import { spawn } from 'node:child_process';
import { exePath, requireExe, run } from './commons.mjs';

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

const server = spawn(exePath(), ['server', '--host', '127.0.0.1', '--port', '0', '--once'], {
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverOut = '';
let serverErr = '';
server.stdout.setEncoding('utf8');
server.stderr.setEncoding('utf8');
server.stdout.on('data', (chunk) => { serverOut += chunk; });
server.stderr.on('data', (chunk) => { serverErr += chunk; });

const ready = await new Promise((resolve) => {
  const timeout = setTimeout(() => resolve(null), 20_000);
  const inspect = () => {
    const line = serverOut.split(/\r?\n/).find((value) => value.trim());
    if (!line) return;
    clearTimeout(timeout);
    try { resolve(JSON.parse(line)); } catch { resolve(null); }
  };
  server.stdout.on('data', inspect);
  server.once('exit', inspect);
});

check(ready?.schema === 'pm.encryption.server.v1', 'server emits ready schema',
  serverOut || serverErr);
check(Number.isInteger(ready?.port) && ready.port > 0, 'server chooses an ephemeral port',
  serverOut);
check(ready?.authenticated_peer === false,
  'harness reports that peer identity is intentionally not authenticated');
check(ready?.mode === 'unauthenticated-kx', 'server reports the unauthenticated feature mode');

function postJson(port, path, body = '') {
  return new Promise((resolve) => {
    const req = request({
      hostname: '127.0.0.1',
      port,
      path,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch { json = null; }
        resolve({ status: res.statusCode ?? 0, json });
      });
    });
    req.on('error', () => resolve({ status: 0, json: null }));
    req.end(body);
  });
}

const denied = ready?.port
  ? await postJson(ready.port, '/v1/e2ee/handshake', '{}')
  : { status: 0, json: null };
check(denied.status === 400 && denied.json?.code === 'unauthenticated_mode',
  'unauthenticated server rejects the identity handshake route',
  JSON.stringify(denied));

const secretPrompt = 'wifi secret: hello from the phone';
let client = { status: -1, json: null, stdout: '', stderr: '' };
if (ready?.port) {
  client = run([
    'client',
    '--url', `http://127.0.0.1:${ready.port}`,
    '--text', secretPrompt,
  ]);
}

check(client.status === 0, 'encrypted client exits 0', client.stdout || client.stderr);
check(client.json?.schema === 'pm.encryption.client.v1', 'client result schema');
check(client.json?.encrypted_frames === 3 && client.json?.done === true,
  'three encrypted SSE frames include terminal DONE', client.stdout);
check(client.json?.assistant === `ack:${Buffer.byteLength(secretPrompt, 'utf8')}`,
  'server decrypted exact request bytes', client.stdout);
check(client.json?.request_frame_bytes > client.json?.request_plaintext_bytes,
  'request crossed HTTP as an authenticated encrypted frame');
check(!client.stdout.includes(secretPrompt) && !serverOut.includes(secretPrompt)
  && !serverErr.includes(secretPrompt), 'process output does not disclose the prompt');

const exitCode = await new Promise((resolve) => {
  const timeout = setTimeout(() => {
    server.kill();
    resolve(-1);
  }, 10_000);
  server.once('exit', (code) => {
    clearTimeout(timeout);
    resolve(code ?? -1);
  });
});
check(exitCode === 0, 'one-shot server exits cleanly', serverErr);

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

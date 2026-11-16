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

function startServer(args) {
  const server = spawn(exePath(), args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let serverOut = '';
  let serverErr = '';
  server.stdout.setEncoding('utf8');
  server.stderr.setEncoding('utf8');
  server.stdout.on('data', (chunk) => { serverOut += chunk; });
  server.stderr.on('data', (chunk) => { serverErr += chunk; });
  return { server, output: () => serverOut, errors: () => serverErr };
}

async function readyLine(child) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 20_000);
    const inspect = () => {
      const line = child.output().split(/\r?\n/).find((value) => value.trim());
      if (!line) return;
      clearTimeout(timeout);
      try { resolve(JSON.parse(line)); } catch { resolve(null); }
    };
    child.server.stdout.on('data', inspect);
    child.server.once('exit', inspect);
  });
}

const seedA = '11'.repeat(32);
const seedB = '22'.repeat(32);
const seedC = '33'.repeat(32);
const identityA = run(['identity', '--seed', seedA]);
const identityB = run(['identity', '--seed', seedB]);
const identityC = run(['identity', '--seed', seedC]);
check(identityA.status === 0 && identityB.status === 0 && identityC.status === 0,
  'deterministic identity keys are available',
  identityA.stdout || identityB.stdout || identityC.stdout);

const secretPrompt = 'wifi secret: authenticated hello';
const mismatch = startServer([
  'server', '--host', '127.0.0.1', '--port', '0',
  '--authenticated', '--identity-seed', seedB, '--peer-key', identityA.json.public_key,
]);
const mismatchReady = await readyLine(mismatch);
let wrong = { status: -1, json: null, stdout: '', stderr: '' };
if (mismatchReady?.port) {
  wrong = run([
    'client', '--url', `http://127.0.0.1:${mismatchReady.port}`,
    '--text', secretPrompt, '--authenticated',
    '--identity-seed', seedA, '--peer-key', identityC.json.public_key,
  ]);
}
check(wrong.status === 1 && wrong.json?.code === 'identity_mismatch',
  'client rejects a peer identity other than the pinned key',
  wrong.stdout || wrong.stderr);
check(!wrong.stdout.includes(secretPrompt) && !mismatch.output().includes(secretPrompt),
  'rejected handshake does not disclose the prompt');
mismatch.server.kill();

const server = startServer([
  'server', '--host', '127.0.0.1', '--port', '0', '--once',
  '--authenticated', '--identity-seed', seedB, '--peer-key', identityA.json.public_key,
]);
const ready = await readyLine(server);
check(ready?.schema === 'pm.encryption.server.v1', 'authenticated server emits ready schema',
  server.output() || server.errors());
check(ready?.mode === 'authenticated-handshake' && ready?.authenticated_peer === true,
  'server reports the authenticated handshake mode', server.output());
check(ready?.handshake === 'sigma-i-v1', 'server names the handshake profile');
check(ready?.identity === identityB.json.public_key, 'server publishes its identity public key');

const denied = ready?.port
  ? await postJson(ready.port, '/v1/e2ee/session', '')
  : { status: 0, json: null };
check(denied.status === 400 && denied.json?.code === 'authenticated_mode',
  'authenticated server rejects the unauthenticated challenge',
  JSON.stringify(denied));

let client = { status: -1, json: null, stdout: '', stderr: '' };
if (ready?.port) {
  client = run([
    'client', '--url', `http://127.0.0.1:${ready.port}`,
    '--text', secretPrompt, '--authenticated',
    '--identity-seed', seedA, '--peer-key', identityB.json.public_key,
  ]);
}

check(client.status === 0, 'authenticated client exits 0', client.stdout || client.stderr);
check(client.json?.authenticated_peer === true, 'client reports a pinned peer');
check(client.json?.encrypted_frames === 3 && client.json?.done === true,
  'encrypted stream still completes after the handshake', client.stdout);
check(client.json?.assistant === `ack:${Buffer.byteLength(secretPrompt, 'utf8')}`,
  'server decrypted the request only after the handshake', client.stdout);
check(!client.stdout.includes(secretPrompt) && !server.output().includes(secretPrompt)
  && !server.errors().includes(secretPrompt),
  'process output does not disclose the prompt');

const exitCode = await new Promise((resolve) => {
  const timeout = setTimeout(() => {
    server.server.kill();
    resolve(-1);
  }, 10_000);
  server.server.once('exit', (code) => {
    clearTimeout(timeout);
    resolve(code ?? -1);
  });
});
check(exitCode === 0, 'one-shot authenticated server exits cleanly', server.errors());

console.log(`\n${failed ? 'FAILED' : 'passed'}: ${failed} failure(s)`);
process.exit(failed ? 1 : 0);

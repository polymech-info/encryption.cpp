import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function exePath() {
  const fromEnv = process.env.PM_ENCRYPTION_CLI;
  if (fromEnv && existsSync(fromEnv)) return resolve(fromEnv);
  const name = process.platform === 'win32' ? 'pm-encryption.exe' : 'pm-encryption';
  for (const dir of ['dev', 'release']) {
    const candidate = join(PKG, 'build', dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return join(PKG, 'build', 'dev', name);
}

export function run(args) {
  const result = spawnSync(exePath(), args, {
    cwd: PKG,
    encoding: 'utf8',
    timeout: 20_000,
  });
  const stdout = String(result.stdout || '').trim();
  let json = null;
  try {
    json = stdout ? JSON.parse(stdout) : null;
  } catch {
    json = null;
  }
  return {
    status: result.status ?? -1,
    stdout,
    stderr: String(result.stderr || ''),
    json,
    spawnError: result.error ? String(result.error.message || result.error) : '',
  };
}

export function requireExe() {
  const exe = exePath();
  if (!existsSync(exe)) {
    console.error(`pm-encryption not built (${exe}). Run: npm run build:cpp`);
    process.exit(1);
  }
  console.log(`pm-encryption  ${exe}`);
}

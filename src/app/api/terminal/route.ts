/**
 * Secure Browser Terminal API
 * POST /api/terminal
 * Body: { command }
 *
 * Security: no shell, no pipes/redirection, base-command allowlist,
 * and filesystem reads limited to explicit safe prefixes.
 */
import { NextRequest, NextResponse } from 'next/server';
import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { OPENCLAW_DIR, OPENCLAW_WORKSPACE } from '@/lib/paths';

const execFileAsync = promisify(execFile);

const ALLOWED_BASE_COMMANDS = new Set([
  'ls', 'cat', 'head', 'tail', 'grep', 'wc', 'find', 'stat', 'du', 'df',
  'ps', 'pgrep', 'pidof', 'top', 'htop',
  'uname', 'hostname', 'whoami', 'id', 'uptime', 'date', 'free',
  'systemctl', 'journalctl',
  'pm2', 'docker',
  'git', 'ping', 'nslookup', 'dig', 'host',
  'netstat', 'ss', 'ip', 'ifconfig', 'lsof',
  'echo', 'printf', 'which', 'type', 'file',
  'sort', 'uniq', 'awk', 'sed', 'tr', 'cut', 'xargs',
  'locate',
]);

const SHELL_META = /[|&;<>()`$\\]/;
const BLOCKED_ARGS: RegExp[] = [
  /^-exec$/,
  /^-delete$/,
  /^--output(?:=.*)?$/,
  /^--config(?:=.*)?$/,
  /^https?:\/\//i,
];

const SAFE_PATH_PREFIXES = [
  `${path.resolve(OPENCLAW_WORKSPACE)}${path.sep}`,
  `${path.resolve(path.join(OPENCLAW_DIR, 'logs'))}${path.sep}`,
  `${path.resolve('/var/log')}${path.sep}`,
  `${path.resolve('/tmp/openclaw')}${path.sep}`,
];

function tokenize(command: string): string[] {
  return command.trim().split(/\s+/).filter(Boolean);
}

function resolveIfPath(arg: string): string | null {
  if (!arg.startsWith('/') && !arg.startsWith('./') && !arg.startsWith('../') && !arg.includes('/')) {
    return null;
  }
  return path.resolve(arg);
}

function isAllowedPath(resolvedPath: string): boolean {
  return SAFE_PATH_PREFIXES.some((prefix) => resolvedPath === prefix.slice(0, -1) || resolvedPath.startsWith(prefix));
}

function validateCommand(command: string): { ok: true; bin: string; args: string[] } | { ok: false; reason: string } {
  const trimmed = command.trim();
  if (!trimmed) return { ok: false, reason: 'No command provided' };
  if (trimmed.length > 500) return { ok: false, reason: 'Command too long' };
  if (SHELL_META.test(trimmed)) return { ok: false, reason: 'Shell operators are not allowed' };

  const tokens = tokenize(trimmed);
  const [bin, ...args] = tokens;

  if (!bin || !ALLOWED_BASE_COMMANDS.has(bin)) {
    return { ok: false, reason: `Command not allowed: "${bin || trimmed}"` };
  }

  for (const arg of args) {
    if (BLOCKED_ARGS.some((pattern) => pattern.test(arg))) {
      return { ok: false, reason: `Blocked argument: ${arg}` };
    }

    const resolvedPath = resolveIfPath(arg);
    if (resolvedPath && !isAllowedPath(resolvedPath)) {
      return { ok: false, reason: `Path not allowed: ${arg}` };
    }
  }

  return { ok: true, bin, args };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const command = String(body.command || '');
    const validated = validateCommand(command);

    if (!validated.ok) {
      return NextResponse.json(
        {
          error: validated.reason,
          hint: 'The terminal only allows single safe commands without shell features, network fetches, or paths outside approved diagnostic locations.',
        },
        { status: 403 }
      );
    }

    const start = Date.now();
    const { stdout, stderr } = await execFileAsync(validated.bin, validated.args, {
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      shell: false,
      cwd: OPENCLAW_WORKSPACE,
      env: {
        ...process.env,
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: process.env.HOME || '/tmp',
        LANG: process.env.LANG || 'C.UTF-8',
      },
    });
    const duration = Date.now() - start;

    return NextResponse.json({
      output: stdout + (stderr ? `\nSTDERR: ${stderr}` : ''),
      duration,
      command: `${validated.bin}${validated.args.length ? ` ${validated.args.join(' ')}` : ''}`,
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return NextResponse.json({ error: msg, output: msg }, { status: 200 });
  }
}

/**
 * Health check endpoint
 * GET /api/health - minimal public liveness, detailed checks only for authenticated users
 */
import { NextRequest, NextResponse } from 'next/server';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { isAuthenticatedRequest } from '@/lib/auth';

const execFileAsync = promisify(execFile);

interface ServiceCheck {
  name: string;
  status: 'up' | 'down' | 'degraded' | 'unknown';
  latency?: number;
  details?: string;
}

async function checkUrl(url: string, timeoutMs = 5000): Promise<{ status: 'up' | 'down'; latency: number; httpCode?: number }> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { signal: controller.signal, cache: 'no-store' });
    clearTimeout(timeout);
    const latency = Date.now() - start;
    return { status: res.ok || res.status < 500 ? 'up' : 'down', latency, httpCode: res.status };
  } catch {
    return { status: 'down', latency: Date.now() - start };
  }
}

async function checkSystemdService(name: string): Promise<ServiceCheck> {
  try {
    const { stdout } = await execFileAsync('systemctl', ['is-active', name], { timeout: 4000 });
    const active = stdout.trim() === 'active';
    return { name, status: active ? 'up' : 'down' };
  } catch {
    return { name, status: 'down' };
  }
}

async function checkPm2Service(name: string): Promise<ServiceCheck> {
  try {
    const { stdout } = await execFileAsync('pm2', ['jlist'], { timeout: 5000, maxBuffer: 1024 * 1024 });
    const list = JSON.parse(stdout);
    const proc = list.find((p: { name: string }) => p.name === name);
    if (!proc) return { name, status: 'unknown' };
    const status = proc.pm2_env?.status === 'online' ? 'up' : 'down';
    return { name, status };
  } catch {
    return { name, status: 'unknown' };
  }
}

export async function GET(request: NextRequest) {
  const timestamp = new Date().toISOString();

  if (!(await isAuthenticatedRequest(request))) {
    return NextResponse.json({
      status: 'ok',
      scope: 'public',
      timestamp,
    });
  }

  const checks: ServiceCheck[] = [];

  const [missionControl, gateway] = await Promise.all([
    checkSystemdService('mission-control'),
    checkSystemdService('openclaw-gateway'),
  ]);
  checks.push({ ...missionControl, name: 'Mission Control' });
  checks.push({ ...gateway, name: 'OpenClaw Gateway' });

  const pm2Services = ['classvault', 'content-vault', 'brain'];
  const pm2Checks = await Promise.all(pm2Services.map(checkPm2Service));
  checks.push(...pm2Checks);

  const anthropic = await checkUrl('https://api.anthropic.com', 3000);
  checks.push({
    name: 'Anthropic API',
    status: anthropic.status === 'up' || anthropic.httpCode === 401 ? 'up' : anthropic.status,
    latency: anthropic.latency,
    details: anthropic.status === 'up' || anthropic.httpCode === 401 ? 'reachable' : 'unreachable',
  });

  const downCount = checks.filter((c) => c.status === 'down').length;
  const overallStatus = downCount === 0 ? 'healthy' : downCount < checks.length / 2 ? 'degraded' : 'critical';

  return NextResponse.json({
    status: overallStatus,
    scope: 'authenticated',
    checks,
    timestamp,
    uptime: Math.floor(process.uptime()),
  });
}

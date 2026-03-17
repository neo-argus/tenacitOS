import type { NextRequest } from "next/server";

const AUTH_COOKIE_NAME = "mc_auth";
const DEFAULT_SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours

interface SessionPayload {
  exp: number;
  nonce: string;
}

function getAuthSecret(): string {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set and at least 32 characters long");
  }
  return secret;
}

function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sign(value: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(getAuthSecret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toHex(new Uint8Array(signature));
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

export async function verifyPassword(password: string): Promise<boolean> {
  const configured = process.env.ADMIN_PASSWORD;
  if (!configured || configured.length < 12) {
    throw new Error("ADMIN_PASSWORD must be set and at least 12 characters long");
  }
  return safeEqual(password, configured);
}

export async function createSessionToken(ttlMs = DEFAULT_SESSION_TTL_MS): Promise<string> {
  const payload: SessionPayload = {
    exp: Date.now() + ttlMs,
    nonce: crypto.randomUUID().replace(/-/g, ""),
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = await sign(encodedPayload);
  return `${encodedPayload}.${signature}`;
}

export async function verifySessionToken(token?: string | null): Promise<boolean> {
  if (!token) return false;

  const [encodedPayload, providedSignature] = token.split(".");
  if (!encodedPayload || !providedSignature) return false;

  const expectedSignature = await sign(encodedPayload);
  if (!safeEqual(providedSignature, expectedSignature)) return false;

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload)) as SessionPayload;
    return Number.isFinite(payload.exp) && payload.exp > Date.now();
  } catch {
    return false;
  }
}

export async function isAuthenticatedRequest(request: NextRequest): Promise<boolean> {
  return verifySessionToken(request.cookies.get(AUTH_COOKIE_NAME)?.value);
}

export const authCookieName = AUTH_COOKIE_NAME;
export const sessionTtlSeconds = DEFAULT_SESSION_TTL_MS / 1000;

import { sign, verify } from 'hono/jwt';
import { base64UrlToBytes, bytesToBase64Url, randomToken, timingSafeEqual, utf8 } from './encoding';
import type { AuthUser, Bindings } from '../types/env';

// Cloudflare Workers' Web Crypto runtime rejects PBKDF2 iteration counts above 100,000.
// Keep this at the platform ceiling so password creation/login does not throw.
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_MAX_ITERATIONS = 100_000;

export async function hashPassword(password: string): Promise<string> {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${bytesToBase64Url(salt)}$${bytesToBase64Url(new Uint8Array(bits))}`;
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, iterationsRaw, saltRaw, hashRaw] = encoded.split('$');
  if (algorithm !== 'pbkdf2_sha256' || !iterationsRaw || !saltRaw || !hashRaw) return false;
  const iterations = Number(iterationsRaw);
  if (!Number.isSafeInteger(iterations) || iterations < 100_000 || iterations > PBKDF2_MAX_ITERATIONS) return false;
  const salt = base64UrlToBytes(saltRaw);
  const expected = base64UrlToBytes(hashRaw);
  const key = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return timingSafeEqual(new Uint8Array(bits), expected);
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', utf8(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function hashOpaqueToken(token: string, pepper: string): Promise<string> {
  return sha256Base64Url(`${token}:${pepper}`);
}

export async function issueAccessToken(user: AuthUser, env: Bindings): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(env.ACCESS_TOKEN_TTL_SECONDS || '900');
  return sign(
    { sub: user.id, role: user.role, publicUserId: user.publicUserId, iat: now, exp: now + ttl, typ: 'access' },
    env.JWT_SECRET,
    'HS256'
  );
}

export async function verifyAccessToken(token: string, env: Bindings): Promise<Record<string, unknown>> {
  return verify(token, env.JWT_SECRET, 'HS256') as Promise<Record<string, unknown>>;
}

async function hmacSignature(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, utf8(payload));
  return bytesToBase64Url(new Uint8Array(signature));
}

export async function issueCapability(input: { publicUserId: string; publicConfigId: string; version: number }, env: Bindings): Promise<string> {
  const payload = bytesToBase64Url(utf8(JSON.stringify({ ...input, typ: 'clip-cap' })));
  const sig = await hmacSignature(payload, env.CAPABILITY_SIGNING_SECRET);
  return `${payload}.${sig}`;
}

export async function verifyCapability(token: string, env: Bindings): Promise<{ publicUserId: string; publicConfigId: string; version: number } | null> {
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = await hmacSignature(payload, env.CAPABILITY_SIGNING_SECRET);
  if (!timingSafeEqual(base64UrlToBytes(signature), base64UrlToBytes(expected))) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload))) as Record<string, unknown>;
    if (parsed.typ !== 'clip-cap' || typeof parsed.publicUserId !== 'string' || typeof parsed.publicConfigId !== 'string' || typeof parsed.version !== 'number') return null;
    return { publicUserId: parsed.publicUserId, publicConfigId: parsed.publicConfigId, version: parsed.version };
  } catch {
    return null;
  }
}

export function newRefreshToken(): string { return randomToken(48); }
export function newSessionToken(): string { return randomToken(32); }

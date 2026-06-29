// CAPTCHA Core Logic — compatible with @cap.js/widget format
//
// Original capjs-core algorithm:
//   - JWT payload: { n: nonce, c: count, s: size, d: difficulty, exp, iat, sk }
//   - Response:    { challenge: { c, s, d }, token, expires }
//   - Salts are NOT in the response — client derives them via FNV-1a PRNG from the token

import type { Env } from './types';
import type { CacheAdapter } from './cache';
import { createCacheAdapter } from './cache';
import { getKey, incrementMetric, storeToken, claimNonce } from './db';
import { buildCachedMinter, getRswKeypair } from './rsw-store';
import { generateInstrumentation, verifyInstrumentationResult, encryptGcm, decryptGcm } from './instrumentation';

// ── random ────────────────────────────────────────────────
function randomHex(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

function randomBase64Url(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlEncode(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s + pad), (c) => c.charCodeAt(0));
}

// ── SHA-256 ───────────────────────────────────────────────
async function sha256(data: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(data)));
}

async function sha256Hex(data: string): Promise<string> {
  const bytes = await sha256(data);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ── HMAC-SHA256 ──────────────────────────────────────────
async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

// ── FNV-1a PRNG (matching original prng.js) ──────────────
function fnv1a(str: string): number {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

function fnv1aResume(state: number, str: string): number {
  let h = state;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }
  return h >>> 0;
}

function prngFromHash(initialHash: number, length: number): string {
  let state = initialHash;
  let result = '';
  while (result.length < length) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    result += state.toString(16).padStart(8, '0');
  }
  return result.substring(0, length);
}

// ── JWT (matching original crypto.js) ────────────────────
const JWT_HEADER_B64 = base64urlEncode(new TextEncoder().encode('{"alg":"HS256","typ":"JWT"}'));

async function jwtSign(payload: Record<string, unknown>, secret: string): Promise<string> {
  const json = JSON.stringify(payload);
  const body = base64urlEncode(new TextEncoder().encode(json));
  const sigInput = `${JWT_HEADER_B64}.${body}`;
  const sig = await hmacSha256(secret, sigInput);
  return `${sigInput}.${base64urlEncode(sig)}`;
}

interface ChallengePayload {
  f?: number;    // format (2 = RSW)
  n?: string;    // nonce (format-1)
  c?: number;    // challenge count
  s?: number;    // salt size
  d?: number;    // difficulty
  exp: number;   // expiry timestamp
  iat: number;   // issued at
  sk?: string;   // siteKey (scope)
  rsw?: { N: string; x: string; t: number };  // format-2 RSW data
  rsw_y?: string; // format-2 expected y
  ei?: string;   // encrypted instrumentation metadata
}

async function jwtVerify(token: string, secret: string): Promise<ChallengePayload | null> {
  if (!token || typeof token !== 'string') return null;
  const firstDot = token.indexOf('.');
  if (firstDot < 1) return null;
  const lastDot = token.lastIndexOf('.');
  if (lastDot === firstDot || token.indexOf('.', firstDot + 1) !== lastDot) return null;

  const sigInput = token.substring(0, lastDot);
  const expected = await hmacSha256(secret, sigInput);
  const actual = base64urlDecode(token.substring(lastDot + 1));

  if (expected.length !== actual.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
  if (diff !== 0) return null;

  try {
    const body = token.substring(firstDot + 1, lastDot);
    return JSON.parse(new TextDecoder().decode(base64urlDecode(body))) as ChallengePayload;
  } catch {
    return null;
  }
}

// ── POW matching (matching original crypto.js) ────────────
interface ParsedPrefix { bytes: Uint8Array; fullBytes: number; partialNibble: number }

function parseHexPrefix(target: string): ParsedPrefix {
  const len = target.length;
  const fullBytes = len >> 1;
  const bytes = new Uint8Array(fullBytes);
  for (let i = 0; i < fullBytes; i++) {
    bytes[i] = parseInt(target.substring(i * 2, i * 2 + 2), 16);
  }
  let partialNibble = -1;
  if (len & 1) {
    const c = target.charCodeAt(len - 1);
    partialNibble = c <= 57 ? c - 48 : (c | 32) - 87;
  }
  return { bytes, fullBytes, partialNibble };
}

function powMatchesPrefix(hashBytes: Uint8Array, parsed: ParsedPrefix): boolean {
  const { bytes, fullBytes, partialNibble } = parsed;
  for (let i = 0; i < fullBytes; i++) {
    if (hashBytes[i] !== bytes[i]) return false;
  }
  if (partialNibble !== -1) {
    const mask = 0xf0;
    if ((hashBytes[fullBytes] & mask) !== (partialNibble << 4)) return false;
  }
  return true;
}

// ── Derive salt & target from token (matching original) ──
function deriveChallenge(token: string, index: number, size: number, difficulty: number): { salt: string; target: string } {
  const tokenFnv = fnv1a(token);
  const idxStr = String(index + 1);
  const saltSeed = fnv1aResume(tokenFnv, idxStr);
  const targetSeed = fnv1aResume(saltSeed, 'd');
  const salt = prngFromHash(saltSeed, size);
  const target = prngFromHash(targetSeed, difficulty);
  return { salt, target };
}

// ── Geo data collection ────────────────────────────────────

interface GeoData {
  country: string;
  asn: string;
  platform: string | null;
  os: string | null;
}

function parseUA(ua: string | null): { platform: string | null; os: string | null } {
  if (!ua) return { platform: null, os: null };

  let os: string | null = null;
  if (/iPad/.test(ua)) os = 'iPadOS';
  else if (/iPhone/.test(ua)) os = 'iOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/Macintosh|Mac OS X/.test(ua)) os = 'macOS';
  else if (/Windows/.test(ua)) os = 'Windows';
  else if (/Linux/.test(ua)) os = 'Linux';

  let platform: string | null = null;
  if (/iPhone|Android.*Mobile|Mobile.*Android/.test(ua)) platform = 'Phone';
  else if (/iPad|Android(?!.*Mobile)|Tablet/.test(ua)) platform = 'Tablet';
  else if (/Macintosh|Windows|Linux|CrOS/.test(ua)) platform = 'Desktop';

  return { platform, os };
}

function collectGeo(request: Request): GeoData {
  const cf = (request as any).cf || {};

  const country = (cf.country as string)?.toUpperCase() || 'unknown';
  const asOrganization = (cf.asOrganization as string) || '';
  const asn = cf.asn ? `AS${cf.asn}` : '';
  const asnLabel = asOrganization ? `${asn} ${asOrganization}` : asn || 'unknown';

  const ua = request.headers.get('User-Agent');
  const { platform, os } = parseUA(ua);

  return { country, asn: asnLabel, platform, os };
}

async function trackGeo(cache: CacheAdapter, siteKey: string, geo: GeoData, enabled = true): Promise<void> {
  if (!enabled) return;
  const ops: Promise<any>[] = [];

  // Use lowercase 'unknown' to match collectGeo() output
  if (geo.country && geo.country !== 'unknown') {
    ops.push(incrementMetric(cache, siteKey, 'country', geo.country));
  }
  if (geo.asn && geo.asn !== 'unknown') {
    ops.push(incrementMetric(cache, siteKey, 'asn', geo.asn));
  }
  if (geo.platform) {
    ops.push(incrementMetric(cache, siteKey, 'platform', geo.platform));
  }
  if (geo.os) {
    ops.push(incrementMetric(cache, siteKey, 'os', geo.os));
  }

  if (ops.length === 0) return;

  // Must await — Cloudflare Workers may cancel fire-and-forget promises after response is sent
  try {
    await Promise.all(ops);
  } catch (err: any) {
    console.error('[cap] trackGeo write failed:', err?.message || err);
  }
}

// ── Public API ────────────────────────────────────────────

const DEFAULT_RSW_T = 75_000;
const MIN_RSW_T = 10_000;
const MAX_RSW_T = 300_000;
const CHALLENGE_TTL_MS = 15 * 60 * 1000;
const TOKEN_TTL_MS = 2 * 60 * 60 * 1000;

export function hourlyBucket(): string {
  return String(Math.floor(Date.now() / 1000 / 3600) * 3600);
}

export async function generateChallenge(env: Env, siteKey: string, request: Request): Promise<Response> {
  const keyData = await getKey(env.DB, siteKey);
  if (!keyData) {
    return Response.json({ error: 'Invalid site key' }, { status: 404 });
  }

  const config = keyData.config;
  const now = Date.now();
  const expires = now + CHALLENGE_TTL_MS;

  // ── RSW mode ──
  if (config.rsw) {
    let rawT = Number(config.rswT) || DEFAULT_RSW_T;
    const t = Math.min(MAX_RSW_T, Math.max(MIN_RSW_T, rawT));

    const minter = buildCachedMinter(t);
    const { x_hex, y_hex } = minter.mint();

    const payload: Record<string, unknown> = {
      f: 2,
      exp: expires,
      iat: now,
      sk: siteKey,
      rsw: { N: minter.N_hex, x: x_hex, t: minter.t },
      rsw_y: y_hex,
    };

    const challenge: any = { protocol: 'rsw', payload: { N: minter.N_hex, x: x_hex, t: minter.t } };

    const token = await jwtSign(payload, keyData.jwtSecret);

    return Response.json({ challenge, token, expires });
  }

  // ── POW mode (default) ──
  const c = config.challengeCount ?? 80;
  const s = config.saltSize ?? 32;
  const d = config.difficulty ?? 4;

  const payload: Record<string, unknown> = {
    n: randomHex(25),
    c,
    s,
    d,
    exp: expires,
    iat: now,
    sk: siteKey,
  };

  const token = await jwtSign(payload, keyData.jwtSecret);

  // Instrumentation
  let instrumentation: string | undefined;
  if (config.instrumentation) {
    const instr = await generateInstrumentation({
      blockAutomatedBrowsers: config.blockAutomatedBrowsers === true,
      ttlMs: CHALLENGE_TTL_MS,
      obfuscationLevel: config.obfuscationLevel ?? 3,
    });
    (payload as any).ei = await encryptGcm({
      id: instr.id,
      expectedVals: instr.expectedVals,
      vars: instr.vars,
      blockAutomatedBrowsers: instr.blockAutomatedBrowsers,
      expires,
    }, keyData.jwtSecret);
    instrumentation = instr.instrumentation;

    // Re-sign the JWT with the encrypted instrumentation data
    const updatedToken = await jwtSign(payload, keyData.jwtSecret);
    const resp: any = {
      challenge: { c, s, d },
      token: updatedToken,
      expires,
      instrumentation,
    };
    return Response.json(resp);
  }

  return Response.json({
    challenge: { c, s, d },
    token,
    expires,
  });
}

export async function validateChallenge(
  env: Env,
  siteKey: string,
  body: { token: string; solutions: number[] },
  request?: Request,
): Promise<Response> {
  const cache = createCacheAdapter(env);
  const metricsEnabled = env.DISABLE_METRICS !== 'true';
  const incMetric = metricsEnabled
    ? (metric: string, bucket: string, amount = 1) => incrementMetric(cache, siteKey, metric, bucket, amount)
    : (_m?: string, _b?: string, _a?: number) => Promise.resolve(0);

  const keyData = await getKey(env.DB, siteKey);
  if (!keyData) {
    return Response.json({ error: 'Invalid site key' }, { status: 404 });
  }

  const jwtSecret = keyData.jwtSecret;
  const payload = await jwtVerify(body.token, jwtSecret);

  if (!payload) {
    await incMetric('failed', hourlyBucket());
    return Response.json({ error: 'Invalid challenge token' }, { status: 403 });
  }

  // Scope check
  if (payload.sk && payload.sk !== siteKey) {
    await incMetric('failed', hourlyBucket());
    return Response.json({ error: 'Challenge token does not match site key' }, { status: 403 });
  }

  // Expiry check
  if (!payload.exp || payload.exp < Date.now()) {
    await incMetric('failed', hourlyBucket());
    return Response.json({ error: 'Challenge expired' }, { status: 403 });
  }

  // ── RSW validation (format-2) ──
  if (payload.f === 2) {
    const rsw = (payload as any).rsw;
    const expectedY = (payload as any).rsw_y as string;
    const claimedY = (body as any).solutions?.[0] as string;

    if (!rsw || !expectedY || !claimedY) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ error: 'Invalid RSW solution' }, { status: 403 });
    }

    const { verifyRswSolution } = await import('./rsw');
    if (!verifyRswSolution(expectedY, claimedY)) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ error: 'Invalid solution' }, { status: 403 });
    }

    // Nonce check
    const sig = body.token.substring(body.token.lastIndexOf('.') + 1);
    const sigHex = Array.from(base64urlDecode(sig), (b) => b.toString(16).padStart(2, '0')).join('');
    const nonceClaimed = await claimNonce(cache, sigHex, 3600);
    if (!nonceClaimed) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ error: 'Challenge already redeemed' }, { status: 403 });
    }

    // Generate redeem token
    const redeemId = randomHex(8);
    const redeemSecret = randomHex(15);
    const redeemToken = `${siteKey}:${redeemId}:${redeemSecret}`;
    const tokenExpires = Date.now() + TOKEN_TTL_MS;

    await storeToken(cache, redeemToken, tokenExpires, 7200);
    await incMetric('verified', hourlyBucket());

    // Track latency
    if (payload.iat) {
      const latencyMs = Date.now() - payload.iat;
      await incMetric('latency_sum', hourlyBucket(), latencyMs);
      await incMetric('latency_count', hourlyBucket(), 1);
    }

    // Track geo data on successful redeem
    if (request) {
      const geo = collectGeo(request);
      await trackGeo(cache, siteKey, geo, metricsEnabled);
    }

    return Response.json({ success: true, token: redeemToken, expires: tokenExpires });
  }

  // ── POW validation (default) ──
  const { c, s, d } = payload;

  // Validate solutions array
  if (!Array.isArray(body.solutions) || body.solutions.length !== c) {
    await incMetric('failed', hourlyBucket());
    return Response.json({ error: 'Invalid solutions' }, { status: 400 });
  }

  // Verify each solution
  for (let i = 0; i < c; i++) {
    if (typeof body.solutions[i] !== 'number') {
      await incMetric('failed', hourlyBucket());
      return Response.json({ error: 'Invalid solutions' }, { status: 400 });
    }

    const derived = deriveChallenge(body.token, i, s!, d!);
    const hashBytes = await sha256(derived.salt + body.solutions[i]);
    const targetPrefix = parseHexPrefix(derived.target);

    if (!powMatchesPrefix(hashBytes, targetPrefix)) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ error: 'Invalid solution' }, { status: 403 });
    }
  }

  // Instrumentation verification (POW path)
  if ((payload as any).ei) {
    const instrMeta = await decryptGcm((payload as any).ei, keyData.jwtSecret);
    if (!instrMeta) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ instr_error: true, error: 'Blocked by instrumentation', reason: 'corrupted_instrumentation_data' }, { status: 403 });
    }
    if (instrMeta.expires && (instrMeta.expires as number) < Date.now()) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ instr_error: true, error: 'Blocked by instrumentation', reason: 'expired' }, { status: 403 });
    }

    const instrBody = (body as any).instr;
    if (instrMeta.blockAutomatedBrowsers && (body as any).instr_blocked === true) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ instr_error: true, error: 'Blocked by instrumentation', reason: 'automated_browser_detected' }, { status: 403 });
    }

    if ((body as any).instr_timeout === true) {
      await incMetric('failed', hourlyBucket());
      return Response.json({ instr_error: true, error: 'Instrumentation timeout', reason: 'timeout' }, { status: 429 });
    }

    if (instrBody) {
      const r = verifyInstrumentationResult(instrMeta as any, instrBody);
      if (!r.valid) {
        await incMetric('failed', hourlyBucket());
        return Response.json({ instr_error: true, error: 'Blocked by instrumentation', reason: r.reason || 'failed_challenge' }, { status: 403 });
      }
    } else {
      await incMetric('failed', hourlyBucket());
      return Response.json({ instr_error: true, error: 'Blocked by instrumentation', reason: 'missing_instrumentation_response' }, { status: 403 });
    }
  }

  // Nonce check (prevent replay) — use JWT signature hex
  const sig = body.token.substring(body.token.lastIndexOf('.') + 1);
  const sigHex = Array.from(base64urlDecode(sig), (b) => b.toString(16).padStart(2, '0')).join('');

  const nonceClaimed = await claimNonce(cache, sigHex, 3600);
  if (!nonceClaimed) {
    await incMetric('failed', hourlyBucket());
    return Response.json({ error: 'Challenge already redeemed' }, { status: 403 });
  }

  // Generate redeem token
  const redeemId = randomHex(8);
  const redeemSecret = randomHex(15);
  const redeemToken = `${siteKey}:${redeemId}:${redeemSecret}`;
  const tokenExpires = Date.now() + TOKEN_TTL_MS;

  await storeToken(cache, redeemToken, tokenExpires, 2 * 3600);
  await incMetric('verified', hourlyBucket());

  // Track latency (ms from challenge issuance to redeem)
  if (payload.iat) {
    const latencyMs = Date.now() - payload.iat;
    await incMetric('latency_sum', hourlyBucket(), latencyMs);
    await incMetric('latency_count', hourlyBucket(), 1);
  }

  // Track geo data on successful redeem
  if (request) {
    const geo = collectGeo(request);
    await trackGeo(cache, siteKey, geo, metricsEnabled);
  }

  return Response.json({
    success: true,
    token: redeemToken,
    expires: tokenExpires,
  });
}

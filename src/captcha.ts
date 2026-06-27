// CAPTCHA Core Logic

import type { Env, KeyConfig } from './types';
import type { CacheAdapter } from './cache';
import { createCacheAdapter } from './cache';
import { getKey, incrementMetric, storeToken, claimNonce } from './db';

// Generate random bytes as hex
function randomHex(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate random bytes as base64url
function randomBase64Url(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// SHA-256 hash as hex
async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// JWT-like token (simplified for Workers)
interface ChallengePayload {
  siteKey: string;
  challenges: Array<{
    id: string;
    salt: string;
    difficulty: number;
  }>;
  expires: number;
  nonce: string;
}

// Simple JWT implementation using Web Crypto
async function signJwt(payload: ChallengePayload, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const data = `${headerB64}.${payloadB64}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${data}.${signatureB64}`;
}

async function verifyJwt(token: string, secret: string): Promise<ChallengePayload | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts;
  const data = `${headerB64}.${payloadB64}`;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  // Decode signature
  const sigStr = signatureB64.replace(/-/g, '+').replace(/_/g, '/');
  const sigPadded = sigStr + '='.repeat((4 - (sigStr.length % 4)) % 4);
  const sigBytes = Uint8Array.from(atob(sigPadded), (c) => c.charCodeAt(0));

  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
  if (!valid) return null;

  // Decode payload
  const payloadStr = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
  const payloadPadded = payloadStr + '='.repeat((4 - (payloadStr.length % 4)) % 4);
  const payload = JSON.parse(atob(payloadPadded)) as ChallengePayload;

  return payload;
}

// Generate challenge
export async function generateChallenge(env: Env, siteKey: string): Promise<Response> {
  const keyData = await getKey(env.DB, siteKey);
  if (!keyData) {
    return Response.json({ error: 'Invalid site key' }, { status: 404 });
  }

  const config = keyData.config;
  const jwtSecret = keyData.jwtSecret;

  // Generate challenges
  const challengeCount = config.challengeCount || 80;
  const saltSize = config.saltSize || 32;
  const difficulty = config.difficulty || 4;

  const challenges = [];
  for (let i = 0; i < challengeCount; i++) {
    challenges.push({
      id: randomHex(8),
      salt: randomHex(saltSize),
      difficulty,
    });
  }

  const now = Date.now();
  const expires = now + 15 * 60 * 1000; // 15 minutes

  const payload: ChallengePayload = {
    siteKey,
    challenges,
    expires,
    nonce: randomHex(16),
  };

  const token = await signJwt(payload, jwtSecret);

  return Response.json({
    token,
    challenges: challenges.map((c) => ({
      id: c.id,
      salt: c.salt,
      difficulty: c.difficulty,
    })),
    expires,
  });
}

// Validate challenge solution
export async function validateChallenge(
  env: Env,
  siteKey: string,
  body: { token: string; solutions: Array<{ id: string; answer: number }> }
): Promise<Response> {
  const cache = createCacheAdapter(env);
  const keyData = await getKey(env.DB, siteKey);
  if (!keyData) {
    return Response.json({ error: 'Invalid site key' }, { status: 404 });
  }

  const jwtSecret = keyData.jwtSecret;
  const payload = await verifyJwt(body.token, jwtSecret);

  if (!payload) {
    await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
    return Response.json({ error: 'Invalid challenge token' }, { status: 403 });
  }

  // Check scope
  if (payload.siteKey !== siteKey) {
    await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
    return Response.json({ error: 'Challenge token does not match site key' }, { status: 403 });
  }

  // Check expiry
  if (payload.expires <= Date.now()) {
    await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
    return Response.json({ error: 'Challenge expired' }, { status: 403 });
  }

  // Verify solutions
  const challengeMap = new Map(payload.challenges.map((c) => [c.id, c]));

  if (!body.solutions || body.solutions.length !== payload.challenges.length) {
    await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
    return Response.json({ error: 'Invalid solutions' }, { status: 400 });
  }

  for (const solution of body.solutions) {
    const challenge = challengeMap.get(solution.id);
    if (!challenge) {
      await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
      return Response.json({ error: 'Invalid solution ID' }, { status: 400 });
    }

    // Verify proof-of-work
    const hash = await sha256(`${challenge.salt}${solution.answer}`);
    const prefix = '0'.repeat(challenge.difficulty);

    if (!hash.startsWith(prefix)) {
      await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
      return Response.json({ error: 'Invalid solution' }, { status: 403 });
    }
  }

  // Check nonce (prevent replay)
  const nonceClaimed = await claimNonce(cache, payload.nonce, 3600);
  if (!nonceClaimed) {
    await incrementMetric(cache, siteKey, 'failed', hourlyBucket());
    return Response.json({ error: 'Challenge already redeemed' }, { status: 403 });
  }

  // Generate redeem token
  const redeemId = randomHex(8);
  const redeemSecret = randomHex(15);
  const redeemToken = `${siteKey}:${redeemId}:${redeemSecret}`;
  const tokenExpires = Date.now() + 2 * 60 * 60 * 1000; // 2 hours

  await storeToken(cache, redeemToken, tokenExpires, 2 * 3600);
  await incrementMetric(cache, siteKey, 'verified', hourlyBucket());

  return Response.json({
    success: true,
    token: redeemToken,
    expires: tokenExpires,
  });
}

function hourlyBucket(): string {
  return String(Math.floor(Date.now() / 1000 / 3600) * 3600);
}

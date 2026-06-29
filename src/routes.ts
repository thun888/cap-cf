// API Routes

import { Hono } from 'hono';
import type { Env, KeyConfig, ChartDuration } from './types';
import type { CacheAdapter } from './cache';
import { createCacheAdapter } from './cache';
import { authMiddleware } from './auth';
import {
  getKey,
  listKeys,
  createKey,
  updateKeyConfig,
  updateKeySecretHash,
  deleteKey,
  keyExists,
  listSessions,
  deleteSession,
  listApiKeys,
  createApiKey,
  deleteApiKey,
  getSetting,
  setSetting,
  getMetrics,
  incrementMetric,
} from './db';
import { generateChallenge, validateChallenge } from './captcha';
import { getRswStatus, ensureRswKeypair } from './rsw-store';

// Helper to generate random hex
function randomHex(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper to generate random base64url
function randomBase64Url(bytes: number): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Helper to hash password using Web Crypto
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Server API routes
export const serverRoutes = new Hono<{ Bindings: Env }>();

// Apply auth middleware to all server routes
serverRoutes.use('*', authMiddleware);

// GET /server/keys - List all keys with metrics
serverRoutes.get('/keys', async (c) => {
  const cache = createCacheAdapter(c.env);
  const keys = await listKeys(c.env.DB);
  const now = Math.floor(Date.now() / 1000);
  const day = 24 * 60 * 60;
  const currentStart = now - day;
  const previousStart = now - 2 * day;

  const result = await Promise.all(
    keys.map(async (key) => {
      const verified = await getMetrics(cache, key.siteKey, 'verified');
      const current = sumSolutions(verified, currentStart);
      const previous = sumSolutions(verified, previousStart, currentStart);

      let change = 0;
      let direction = '';
      if (previous > 0) {
        change = ((current - previous) / previous) * 100;
        direction = current > previous ? 'up' : current < previous ? 'down' : '';
      } else if (current > 0) {
        change = 100;
        direction = 'up';
      }

      return {
        siteKey: key.siteKey,
        name: key.name,
        created: key.createdAt,
        solvesLast24h: current,
        difference: {
          value: change.toFixed(2),
          direction,
        },
      };
    })
  );

  return c.json(result);
});

// POST /server/keys - Create new key
serverRoutes.post('/keys', async (c) => {
  const body = await c.req.json();

  const siteKey = randomHex(5);
  const secretKey = `sk-${randomBase64Url(32)}`;
  const jwtSecret = randomBase64Url(32);

  const config: KeyConfig = {
    difficulty: body.difficulty ?? 4,
    challengeCount: body.challengeCount ?? 80,
    saltSize: 32,
    instrumentation: body.instrumentation ?? false,
    obfuscationLevel: body.obfuscationLevel ?? 3,
    blockAutomatedBrowsers: body.blockAutomatedBrowsers ?? false,
    rsw: body.rsw ?? false,
    rswT: body.rswT ?? 75000,
    ...(body.corsOrigins && Array.isArray(body.corsOrigins) && body.corsOrigins.length
      ? { corsOrigins: body.corsOrigins }
      : {}),
  };

  const secretHash = await hashPassword(secretKey);

  await createKey(c.env.DB, siteKey, body.name || siteKey, secretHash, jwtSecret, config);

  return c.json({ siteKey, secretKey });
});

// GET /server/keys/:siteKey - Get key details
serverRoutes.get('/keys/:siteKey', async (c) => {
  const cache = createCacheAdapter(c.env);
  const siteKey = c.req.param('siteKey');
  const chartDuration = (c.req.query('chartDuration') || 'today') as ChartDuration;

  const key = await getKey(c.env.DB, siteKey);
  if (!key) {
    return c.json({ success: false, error: 'Key not found' }, 404);
  }

  const now = Math.floor(Date.now() / 1000);
  const day = 86400;

  let bucketSize: number, startTime: number, endTime: number;
  switch (chartDuration) {
    case 'today':
      bucketSize = 3600;
      startTime = Math.floor(now / day) * day;
      endTime = Math.floor(now / 3600) * 3600 + 3600;
      break;
    case 'yesterday':
      bucketSize = 3600;
      startTime = Math.floor(now / day) * day - day;
      endTime = startTime + day;
      break;
    case 'last7days':
      bucketSize = day;
      startTime = Math.floor((now - 7 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case 'last28days':
      bucketSize = day;
      startTime = Math.floor((now - 28 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case 'last91days':
      bucketSize = day;
      startTime = Math.floor((now - 91 * day) / day) * day;
      endTime = Math.floor(now / day) * day + day;
      break;
    case 'alltime':
      bucketSize = day;
      startTime = 0;
      endTime = now + day;
      break;
    default:
      bucketSize = 3600;
      startTime = now - day;
      endTime = now + 3600;
  }

  const [verifiedH, failedH, latSumH, latCountH] = await Promise.all([
    getMetrics(cache, siteKey, 'verified'),
    getMetrics(cache, siteKey, 'failed'),
    getMetrics(cache, siteKey, 'latency_sum'),
    getMetrics(cache, siteKey, 'latency_count'),
  ]);

  const totalVerified = sumSolutions(verifiedH, startTime, endTime);
  const totalFailed = sumSolutions(failedH, startTime, endTime);
  const totalLatSum = sumSolutions(latSumH, startTime, endTime);
  const totalLatCount = sumSolutions(latCountH, startTime, endTime);
  const avgLatency = totalLatCount > 0 ? Math.round(totalLatSum / totalLatCount) : 0;

  const chartData = buildChartData(verifiedH, failedH, startTime, endTime, bucketSize, chartDuration, now, day);

  return c.json({
    key: {
      siteKey: key.siteKey,
      name: key.name,
      created: key.createdAt,
      config: key.config,
    },
    stats: {
      challenges: totalVerified + totalFailed,
      verified: totalVerified,
      failed: totalFailed,
      avgLatency,
    },
    chartData: {
      duration: chartDuration,
      bucketSize,
      data: chartData,
    },
  });
});

// PUT /server/keys/:siteKey/config - Update key config
serverRoutes.put('/keys/:siteKey/config', async (c) => {
  const siteKey = c.req.param('siteKey');
  const body = await c.req.json();

  const key = await getKey(c.env.DB, siteKey);
  if (!key) {
    return c.json({ success: false, error: 'Key not found' }, 404);
  }

  const config: KeyConfig = {
    ...key.config,
    difficulty: body.difficulty ?? key.config.difficulty,
    challengeCount: body.challengeCount ?? key.config.challengeCount,
    saltSize: 32,
    instrumentation: body.instrumentation ?? key.config.instrumentation,
    obfuscationLevel: body.obfuscationLevel ?? key.config.obfuscationLevel,
    blockAutomatedBrowsers: body.blockAutomatedBrowsers ?? key.config.blockAutomatedBrowsers,
    corsOrigins: body.corsOrigins !== undefined ? body.corsOrigins : key.config.corsOrigins,
    rsw: body.rsw ?? key.config.rsw,
    rswT: body.rswT ?? key.config.rswT,
  };

  await updateKeyConfig(c.env.DB, siteKey, body.name || null, config);

  return c.json({ success: true });
});

// DELETE /server/keys/:siteKey - Delete key
serverRoutes.delete('/keys/:siteKey', async (c) => {
  const siteKey = c.req.param('siteKey');

  const exists = await keyExists(c.env.DB, siteKey);
  if (!exists) {
    return c.json({ success: false, error: 'Key not found' }, 404);
  }

  await deleteKey(c.env.DB, siteKey);

  return c.json({ success: true });
});

// POST /server/keys/:siteKey/rotate-secret - Rotate secret key
serverRoutes.post('/keys/:siteKey/rotate-secret', async (c) => {
  const siteKey = c.req.param('siteKey');

  const exists = await keyExists(c.env.DB, siteKey);
  if (!exists) {
    return c.json({ success: false, error: 'Key not found' }, 404);
  }

  const newSecretKey = `sk-${randomBase64Url(32)}`;
  const secretHash = await hashPassword(newSecretKey);

  await updateKeySecretHash(c.env.DB, siteKey, secretHash);

  return c.json({ secretKey: newSecretKey });
});

// GET /server/keys/:siteKey/geo-stats - Geo statistics
serverRoutes.get('/keys/:siteKey/geo-stats', async (c) => {
  const cache = createCacheAdapter(c.env);
  const siteKey = c.req.param('siteKey');

  const [countryData, asnData, platformData, osData] = await Promise.all([
    getMetrics(cache, siteKey, 'country'),
    getMetrics(cache, siteKey, 'asn'),
    getMetrics(cache, siteKey, 'platform'),
    getMetrics(cache, siteKey, 'os'),
  ]);

  const countries = Object.entries(countryData)
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);

  const asns = Object.entries(asnData)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const platforms = Object.entries(platformData)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const oses = Object.entries(osData)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  return c.json({
    countries,
    totalCountry: countries.reduce((s, c) => s + c.count, 0),
    asns,
    totalAsn: asns.reduce((s, a) => s + a.count, 0),
    platforms,
    totalPlatform: platforms.reduce((s, p) => s + p.count, 0),
    oses,
    totalOs: oses.reduce((s, o) => s + o.count, 0),
  });
});

// GET /server/settings/sessions - List sessions
serverRoutes.get('/settings/sessions', async (c) => {
  const sessions = await listSessions(c.env.DB);
  return c.json(
    sessions.map((s) => ({
      token: s.hash.slice(-14),
      expires: new Date(s.expires).toISOString(),
      created: new Date(s.created).toISOString(),
    }))
  );
});

// GET /server/settings/apikeys - List API keys
serverRoutes.get('/settings/apikeys', async (c) => {
  const apiKeys = await listApiKeys(c.env.DB);
  return c.json(
    apiKeys.map((k) => ({
      name: k.name,
      id: k.id,
      created: new Date(k.createdAt * 1000).toISOString(),
    }))
  );
});

// POST /server/settings/apikeys - Create API key
serverRoutes.post('/settings/apikeys', async (c) => {
  const body = await c.req.json();

  const id = randomHex(16);
  const token = randomBase64Url(32);
  const tokenHash = await hashPassword(token);

  await createApiKey(c.env.DB, id, body.name, tokenHash);

  return c.json({ apiKey: `${id}_${token}` });
});

// DELETE /server/settings/apikeys/:id - Delete API key
serverRoutes.delete('/settings/apikeys/:id', async (c) => {
  const id = c.req.param('id');
  await deleteApiKey(c.env.DB, id);
  return c.json({ success: true });
});

// GET /server/settings/cors - Get CORS settings
serverRoutes.get('/settings/cors', async (c) => {
  const raw = await getSetting(c.env.DB, 'cors');
  if (!raw) return c.json({ origins: null });
  try {
    return c.json(JSON.parse(raw));
  } catch {
    return c.json({ origins: null });
  }
});

// PUT /server/settings/cors - Update CORS settings
serverRoutes.put('/settings/cors', async (c) => {
  const body = await c.req.json();
  const settings = { origins: body.origins ?? null };
  await setSetting(c.env.DB, 'cors', JSON.stringify(settings));
  return c.json({ success: true });
});

// GET /server/settings/rsw - Get RSW status
serverRoutes.get('/settings/rsw', (c) => {
  return c.json(getRswStatus());
});

// POST /server/settings/rsw/ensure - Generate RSW keypair if needed
serverRoutes.post('/settings/rsw/ensure', async (c) => {
  try {
    const next = await ensureRswKeypair(c.env.DB);
    return c.json({ success: true, ...next });
  } catch (e: any) {
    console.error('[cap] RSW keypair generation failed:', e);
    return c.json({ success: false, error: 'Generation failed' }, 500);
  }
});

// GET /server/about - Get server info
serverRoutes.get('/about', (c) => {
  return c.json({
    runtime: 'Cloudflare Workers',
    version: '1.0.0',
    cacheBackend: c.env.CACHE_BACKEND || 'd1',
  });
});

// POST /server/logout - Logout session
serverRoutes.post('/logout', async (c) => {
  const authHeader = c.req.header('authorization');
  if (!authHeader) {
    return c.json({ success: false, error: 'Unauthorized' }, 401);
  }

  const body = await c.req.json().catch(() => ({}));

  // Decode the Bearer token to get the session hash
  let session = '';
  try {
    let encoded = authHeader.slice(7).trim();
    while (encoded.length % 4 !== 0) encoded += '=';
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const { hash } = JSON.parse(atob(encoded));
    session = hash;
  } catch {
    return c.json({ success: false, error: 'Unauthorized' }, 401);
  }

  // If a specific session is provided, find it
  if (body.session) {
    if (body.session.length < 10) {
      return c.json({ success: false, error: 'Session code too short' });
    }

    const sessions = await listSessions(c.env.DB);
    const match = sessions.find((s) => s.hash.endsWith(body.session));
    if (!match) {
      return c.json({ success: false, error: 'Session not found' }, 404);
    }
    session = match.hash;
  }

  await deleteSession(c.env.DB, session);

  return c.json({ success: true });
});

// Challenge API routes (public, no auth required)
export const challengeRoutes = new Hono<{ Bindings: Env }>();

// POST /:siteKey/challenge - Generate challenge
challengeRoutes.post('/:siteKey/challenge', async (c) => {
  const siteKey = c.req.param('siteKey');
  return generateChallenge(c.env, siteKey, c.req.raw);
});

// POST /:siteKey/redeem - Validate challenge
challengeRoutes.post('/:siteKey/redeem', async (c) => {
  const siteKey = c.req.param('siteKey');
  const body = await c.req.json();

  if (!body.token || !body.solutions) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  return validateChallenge(c.env, siteKey, body, c.req.raw);
});

// Siteverify API (for external verification)
export const siteverifyRoutes = new Hono<{ Bindings: Env }>();

// POST /siteverify or /:siteKey/siteverify
// Accepts both JSON and form-urlencoded bodies
siteverifyRoutes.post('/', async (c) => {
  const cache = createCacheAdapter(c.env);

  // Parse body — accepts both form-urlencoded and JSON
  let body: Record<string, string> = {};
  const contentType = c.req.header('content-type') || '';
  if (contentType.includes('application/json')) {
    body = await c.req.json();
  } else {
    const text = await c.req.text();
    for (const pair of text.split('&')) {
      const [key, val] = pair.split('=');
      if (key) body[decodeURIComponent(key)] = decodeURIComponent(val || '');
    }
  }

  const secret = body.secret;
  const response = body.response;

  if (!secret || !response) {
    return c.json({ success: false, error: 'Missing required parameters' }, 400);
  }

  // Parse the response token: siteKey:redeemId:redeemSecret
  const parts = response.split(':');
  if (parts.length !== 3) {
    return c.json({ success: false, error: 'Invalid token format' }, 400);
  }

  // Use siteKey from URL path if present, otherwise from token
  const urlSiteKey = c.req.param('siteKey');
  const siteKey = urlSiteKey || parts[0];

  // If URL has siteKey, verify token matches
  if (urlSiteKey && !response.startsWith(urlSiteKey)) {
    return c.json({ success: false, error: 'Invalid site key or secret' }, 404);
  }

  // Get key data
  const keyData = await getKey(c.env.DB, siteKey);
  if (!keyData) {
    return c.json({ success: false, error: 'Invalid site key or secret' }, 404);
  }

  // Verify secret
  const secretHash = await hashPassword(secret);
  if (secretHash !== keyData.secretHash) {
    return c.json({ success: false, error: 'Invalid site key or secret' }, 403);
  }

  // Check token exists (one-time use)
  const tokenKey = `token:${response}`;
  const tokenExists = await cache.get(tokenKey);

  if (!tokenExists) {
    return c.json({ success: false, error: 'Token not found' }, 404);
  }

  // Delete token (one-time use)
  await cache.delete(tokenKey);

  return c.json({ success: true });
});

// Auth routes
export const authRoutes = new Hono<{ Bindings: Env }>();

// POST /auth/login - Login
authRoutes.post('/login', async (c) => {
  const body = await c.req.json();
  const adminKey = c.env.ADMIN_KEY;

  if (!adminKey) {
    return c.json({ success: false, error: 'Admin key not configured' }, 500);
  }

  if (body.admin_key !== adminKey) {
    return c.json({ success: false }, 401);
  }

  // Generate session
  const sessionToken = randomHex(30);
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  const created = Date.now();

  const tokenHash = await hashPassword(sessionToken);

  const { createSession } = await import('./db');
  await createSession(c.env.DB, tokenHash, { created, expires });

  return c.json({
    success: true,
    session_token: sessionToken,
    hashed_token: tokenHash,
    expires,
  });
});

// Helper functions
function sumSolutions(data: Record<string, number>, start: number, end?: number): number {
  let sum = 0;
  for (const [bucketStr, count] of Object.entries(data)) {
    const bucket = Number(bucketStr);
    if (bucket >= start && (end === undefined || bucket < end)) {
      sum += count;
    }
  }
  return sum;
}

function buildChartData(
  verified: Record<string, number>,
  failed: Record<string, number>,
  startTime: number,
  endTime: number,
  bucketSize: number,
  duration: ChartDuration,
  now: number,
  day: number
) {
  const chartData = [];

  if (bucketSize === day) {
    const numDays =
      duration === 'last7days' ? 7 : duration === 'last28days' ? 28 : duration === 'last91days' ? 91 : undefined;

    if (numDays) {
      const currentDayStart = Math.floor(now / day) * day;
      for (let i = 0; i < numDays; i++) {
        const b = currentDayStart - (numDays - 1 - i) * day;
        chartData.push({
          bucket: b,
          challenges: (verified[b] || 0) + (failed[b] || 0),
          verified: verified[b] || 0,
          failed: failed[b] || 0,
        });
      }
    } else {
      const allBuckets = new Set([...Object.keys(verified), ...Object.keys(failed)]);
      for (const b of [...allBuckets].map(Number).sort((a, c) => a - c)) {
        chartData.push({
          bucket: b,
          challenges: (verified[b] || 0) + (failed[b] || 0),
          verified: verified[b] || 0,
          failed: failed[b] || 0,
        });
      }
    }
  } else {
    const startHour = Math.floor(startTime / 3600);
    const endHour = Math.floor((endTime - 1) / 3600);
    for (let h = startHour; h <= endHour; h++) {
      const b = h * 3600;
      chartData.push({
        bucket: b,
        challenges: (verified[b] || 0) + (failed[b] || 0),
        verified: verified[b] || 0,
        failed: failed[b] || 0,
      });
    }
  }

  return chartData;
}

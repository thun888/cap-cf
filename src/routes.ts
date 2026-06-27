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
  getBlockedIps,
  blockIp,
  unblockIp,
  getMetrics,
  incrementMetric,
} from './db';
import { generateChallenge, validateChallenge } from './captcha';

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
    difficulty: 4,
    challengeCount: 80,
    saltSize: 32,
    instrumentation: false,
    obfuscationLevel: 3,
    blockAutomatedBrowsers: false,
    rsw: false,
    rswT: 75000,
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

  const [verifiedH, failedH, ratelimitedH] = await Promise.all([
    getMetrics(cache, siteKey, 'verified'),
    getMetrics(cache, siteKey, 'failed'),
    getMetrics(cache, siteKey, 'ratelimited'),
  ]);

  const totalVerified = sumSolutions(verifiedH, startTime, endTime);
  const totalFailed = sumSolutions(failedH, startTime, endTime);
  const totalRateLimited = sumSolutions(ratelimitedH, startTime, endTime);

  const chartData = buildChartData(verifiedH, failedH, ratelimitedH, startTime, endTime, bucketSize, chartDuration, now, day);

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
      avgLatency: 0,
      rateLimited: totalRateLimited,
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
    ratelimitMax: body.ratelimitMax !== undefined ? body.ratelimitMax : key.config.ratelimitMax,
    ratelimitDuration: body.ratelimitDuration !== undefined ? body.ratelimitDuration : key.config.ratelimitDuration,
    corsOrigins: body.corsOrigins !== undefined ? body.corsOrigins : key.config.corsOrigins,
    blockNonBrowserUA: body.blockNonBrowserUA !== undefined ? body.blockNonBrowserUA : key.config.blockNonBrowserUA,
    requiredHeaders: body.requiredHeaders !== undefined ? body.requiredHeaders : key.config.requiredHeaders,
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

// GET /server/keys/:siteKey/blocked-ips - List blocked IPs
serverRoutes.get('/keys/:siteKey/blocked-ips', async (c) => {
  const siteKey = c.req.param('siteKey');
  const blocked = await getBlockedIps(c.env.DB, siteKey);
  return c.json(blocked);
});

// POST /server/keys/:siteKey/block-ip - Block IP
serverRoutes.post('/keys/:siteKey/block-ip', async (c) => {
  const siteKey = c.req.param('siteKey');
  const body = await c.req.json();

  const exists = await keyExists(c.env.DB, siteKey);
  if (!exists) {
    return c.json({ success: false, error: 'Key not found' }, 404);
  }

  const type = body.type || 'ip';
  let key: string;
  if (type === 'ip') key = body.ip || body.value;
  else if (type === 'cidr') key = `cidr:${body.value}`;
  else if (type === 'asn') key = `asn:${body.value}`;
  else if (type === 'country') key = `country:${body.value}`;
  else return c.json({ success: false, error: 'Invalid block type' }, 400);

  if (!key) {
    return c.json({ success: false, error: 'Missing value' }, 400);
  }

  const duration = body.duration || 0;
  await blockIp(c.env.DB, siteKey, key, duration);

  return c.json({ success: true });
});

// POST /server/keys/:siteKey/unblock-ip - Unblock IP
serverRoutes.post('/keys/:siteKey/unblock-ip', async (c) => {
  const siteKey = c.req.param('siteKey');
  const body = await c.req.json();

  const type = body.type || 'ip';
  let key: string;
  if (type === 'ip') key = body.ip || body.value;
  else if (type === 'cidr') key = `cidr:${body.value}`;
  else if (type === 'asn') key = `asn:${body.value}`;
  else if (type === 'country') key = `country:${body.value}`;
  else key = body.ip;

  if (!key) {
    return c.json({ success: false, error: 'Missing value' }, 400);
  }

  await unblockIp(c.env.DB, siteKey, key);

  return c.json({ success: true });
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

// GET /server/settings/headers - Get header settings
serverRoutes.get('/settings/headers', async (c) => {
  const raw = await getSetting(c.env.DB, 'headers');
  if (!raw) return c.json({ ipHeader: '', countryHeader: '', asnHeader: '' });
  try {
    return c.json(JSON.parse(raw));
  } catch {
    return c.json({ ipHeader: '', countryHeader: '', asnHeader: '' });
  }
});

// PUT /server/settings/headers - Update header settings
serverRoutes.put('/settings/headers', async (c) => {
  const body = await c.req.json();
  const settings = {
    ipHeader: body.ipHeader || '',
    countryHeader: body.countryHeader || '',
    asnHeader: body.asnHeader || '',
  };
  await setSetting(c.env.DB, 'headers', JSON.stringify(settings));
  return c.json({ success: true });
});

// GET /server/settings/ratelimit - Get rate limit settings
serverRoutes.get('/settings/ratelimit', async (c) => {
  const raw = await getSetting(c.env.DB, 'ratelimit');
  if (!raw) return c.json({ max: 30, duration: 5000 });
  try {
    return c.json(JSON.parse(raw));
  } catch {
    return c.json({ max: 30, duration: 5000 });
  }
});

// PUT /server/settings/ratelimit - Update rate limit settings
serverRoutes.put('/settings/ratelimit', async (c) => {
  const body = await c.req.json();
  const settings = {
    max: body.max ?? 30,
    duration: body.duration ?? 5000,
  };
  await setSetting(c.env.DB, 'ratelimit', JSON.stringify(settings));
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

// GET /server/about - Get server info
serverRoutes.get('/about', (c) => {
  return c.json({
    runtime: 'Cloudflare Workers',
    version: '1.0.0',
    cacheBackend: c.env.CACHE_BACKEND || 'd1',
  });
});

// Challenge API routes (public, no auth required)
export const challengeRoutes = new Hono<{ Bindings: Env }>();

// POST /:siteKey/challenge - Generate challenge
challengeRoutes.post('/:siteKey/challenge', async (c) => {
  const siteKey = c.req.param('siteKey');
  return generateChallenge(c.env, siteKey);
});

// POST /:siteKey/redeem - Validate challenge
challengeRoutes.post('/:siteKey/redeem', async (c) => {
  const siteKey = c.req.param('siteKey');
  const body = await c.req.json();

  if (!body.token || !body.solutions) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  return validateChallenge(c.env, siteKey, body);
});

// Siteverify API (for external verification)
export const siteverifyRoutes = new Hono<{ Bindings: Env }>();

// POST /siteverify - Verify token
siteverifyRoutes.post('/', async (c) => {
  const cache = createCacheAdapter(c.env);
  const body = await c.req.json();

  if (!body.secret || !body.response) {
    return c.json({ success: false, error: 'Missing required fields' }, 400);
  }

  // Parse the response token
  const parts = body.response.split(':');
  if (parts.length !== 3) {
    return c.json({ success: false, error: 'Invalid token format' }, 400);
  }

  const [siteKey, redeemId, redeemSecret] = parts;

  // Get key data
  const keyData = await getKey(c.env.DB, siteKey);
  if (!keyData) {
    return c.json({ success: false, error: 'Invalid site key' }, 400);
  }

  // Verify secret
  const secretHash = await hashPassword(body.secret);
  if (secretHash !== keyData.secretHash) {
    return c.json({ success: false, error: 'Invalid secret' }, 400);
  }

  // Check token exists
  const tokenKey = `token:${body.response}`;
  const tokenExists = await cache.get(tokenKey);

  if (!tokenExists) {
    return c.json({ success: false, error: 'Token expired or already used' }, 400);
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
  ratelimited: Record<string, number>,
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
          rateLimited: ratelimited[b] || 0,
        });
      }
    } else {
      const allBuckets = new Set([...Object.keys(verified), ...Object.keys(failed), ...Object.keys(ratelimited)]);
      for (const b of [...allBuckets].map(Number).sort((a, c) => a - c)) {
        chartData.push({
          bucket: b,
          challenges: (verified[b] || 0) + (failed[b] || 0),
          verified: verified[b] || 0,
          failed: failed[b] || 0,
          rateLimited: ratelimited[b] || 0,
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
        rateLimited: ratelimited[b] || 0,
      });
    }
  }

  return chartData;
}

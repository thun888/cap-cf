/**
 * Cap CF - Cloudflare Workers CAPTCHA Service
 *
 * This is the main entry point for the Cloudflare Worker.
 * It sets up all routes and handles CORS.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { serverRoutes, challengeRoutes, siteverifyRoutes, authRoutes } from './routes';
import { loadRswKeypair } from './rsw-store';
import { handleAsset } from './assets';

// Startup initialization — runs once at cold start
let rswInitPromise: Promise<void> | null = null;

function initWorker(env: Env): void {
  if (!rswInitPromise) {
    rswInitPromise = loadRswKeypair(env.DB).catch((e) =>
      console.warn('[cap] RSW keypair load:', e.message),
    );
  }
}

const app = new Hono<{ Bindings: Env }>();

// CORS middleware
app.use('*', async (c, next) => {
  const origin = c.req.header('origin');
  const path = new URL(c.req.url).pathname;

  // Allow assets requests
  if (path === '/assets' || path.startsWith('/assets/')) {
    await next();
    return;
  }

  // For other requests, check CORS config
  const corsHandler = cors({
    origin: (origin) => {
      return origin || '*';
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  });

  return corsHandler(c, next);
});

// API routes
app.route('/auth', authRoutes);
app.route('/server', serverRoutes);
app.route('/siteverify', siteverifyRoutes);

// Assets proxy
app.get('/assets/:filename', async (c) => {
  const env = c.env as unknown as Env;
  const result = await handleAsset(c.req.raw, env, c.executionCtx as any, c.req.param('filename'));
  if (!result) return c.notFound();
  return result;
});

// Challenge routes (public)
app.route('/', challengeRoutes);


// Handle 404
app.notFound((c) => {
  return c.json({ success: false, error: 'Not found' }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error('Error:', err);
  return c.json(
    {
      success: false,
      error: 'Internal server error',
      message: err.message,
    },
    500
  );
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    initWorker(env);
    return app.fetch(request, env, ctx);
  },
};

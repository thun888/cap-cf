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
      // You can customize this based on your needs
      return origin || '*';
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  });

  return corsHandler(c, next);
});

// Health check
app.get('/', (c) => {
  return c.json({ status: 'ok', service: 'Cap CF' });
});

// Mount routes
app.route('/auth', authRoutes);
app.route('/server', serverRoutes);
app.route('/', challengeRoutes);
app.route('/siteverify', siteverifyRoutes);

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
    return app.fetch(request, env, ctx);
  },
};

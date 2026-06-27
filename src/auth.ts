// Authentication middleware

import type { Context, Next } from 'hono';
import type { Env } from './types';
import { getSession, getApiKey } from './db';

export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const authHeader = c.req.header('authorization');

  if (!authHeader) {
    return c.json(
      {
        success: false,
        error: 'Unauthorized. An API key or session token is required.',
      },
      401
    );
  }

  // Bot token (API key)
  if (authHeader.startsWith('Bot ')) {
    const botToken = authHeader.slice(4).trim();
    const [id, token] = botToken.split('_');

    if (!id || !token) {
      return c.json(
        {
          success: false,
          error: 'Unauthorized. Invalid bot token.',
        },
        401
      );
    }

    const apiKey = await getApiKey(c.env.DB, id);
    if (!apiKey) {
      return c.json(
        {
          success: false,
          error: 'Unauthorized. Deleted or non-existent bot token.',
        },
        401
      );
    }

    // Verify token hash
    const encoder = new TextEncoder();
    const data = encoder.encode(token);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    if (hashHex !== apiKey.tokenHash) {
      return c.json(
        {
          success: false,
          error: 'Unauthorized. Invalid bot token.',
        },
        401
      );
    }

    await next();
    return;
  }

  // Session token
  if (!authHeader.startsWith('Bearer ')) {
    return c.json(
      {
        success: false,
        error: 'Unauthorized. Invalid authorization format.',
      },
      401
    );
  }

  let token: string, hash: string;
  try {
    const decoded = atob(authHeader.slice(8).trim());
    ({ token, hash } = JSON.parse(decoded));
  } catch {
    return c.json(
      {
        success: false,
        error: 'Unauthorized. Malformed session token.',
      },
      401
    );
  }

  const session = await getSession(c.env.DB, hash);
  if (!session) {
    return c.json(
      {
        success: false,
        error: 'Unauthorized. An invalid session token was used.',
      },
      401
    );
  }

  // Verify token
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const tokenHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  if (tokenHash !== hash) {
    return c.json(
      {
        success: false,
        error: 'Unauthorized. An invalid session token was used.',
      },
      401
    );
  }

  await next();
}

export async function requireAdminKey(c: Context<{ Bindings: Env }>, next: Next) {
  const adminKey = c.env.ADMIN_KEY;

  if (!adminKey) {
    return c.json({ success: false, error: 'Admin key not configured' }, 500);
  }

  const authHeader = c.req.header('authorization');
  if (!authHeader) {
    return c.json({ success: false, error: 'Unauthorized' }, 401);
  }

  // Check if it's a valid session or API key
  if (authHeader.startsWith('Bot ') || authHeader.startsWith('Bearer ')) {
    await next();
    return;
  }

  return c.json({ success: false, error: 'Unauthorized' }, 401);
}

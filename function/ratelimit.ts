import type { Env } from './types';

export interface RateLimitVerdict {
  allowed: boolean;
  remaining: number;
  limit: number;
  /** True when no KV namespace is bound, so nothing is enforced. */
  unenforced: boolean;
}

/**
 * Per-user daily quota. Without a KV binding this is a no-op, which is fine
 * for a hobby deployment but not for a public bot - bind CACHE in production.
 */
export async function checkRateLimit(env: Env, userId: number): Promise<RateLimitVerdict> {
  const limit = Number.parseInt(env.MAX_SCANS_PER_DAY ?? '40', 10) || 40;
  if (!env.CACHE) return { allowed: true, remaining: limit, limit, unenforced: true };

  const day = new Date().toISOString().slice(0, 10);
  const key = `rl:${userId}:${day}`;
  const current = Number.parseInt((await env.CACHE.get(key)) ?? '0', 10) || 0;

  if (current >= limit) return { allowed: false, remaining: 0, limit, unenforced: false };

  await env.CACHE.put(key, String(current + 1), { expirationTtl: 90_000 });
  return { allowed: true, remaining: limit - current - 1, limit, unenforced: false };
}

/** Cache a finished scan so a repeat link answers instantly. */
export async function readCachedScan(env: Env, key: string): Promise<unknown | null> {
  if (!env.CACHE) return null;
  try {
    return await env.CACHE.get(key, 'json');
  } catch {
    return null;
  }
}

export async function writeCachedScan(env: Env, key: string, value: unknown, ttlSeconds = 6 * 60 * 60): Promise<void> {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(key, JSON.stringify(value), { expirationTtl: ttlSeconds });
  } catch {
    // caching is best-effort
  }
}

/** Remember the last link per chat so buttons can re-scan without state. */
export async function rememberLastUrl(env: Env, chatId: number, url: string): Promise<void> {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(`last:${chatId}`, url, { expirationTtl: 86_400 });
  } catch {
    // ignore
  }
}

export async function recallLastUrl(env: Env, chatId: number): Promise<string | null> {
  if (!env.CACHE) return null;
  try {
    return await env.CACHE.get(`last:${chatId}`);
  } catch {
    return null;
  }
}

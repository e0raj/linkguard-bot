import type { Env, TelegramUpdate } from './types';
import { analyzeLink } from './analyze';
import { handleUpdate } from './telegram';
import { buildReport } from './report';

/**
 * LinkGuard worker entry point.
 *
 *   POST /webhook   Telegram updates (secret-token protected)
 *   GET  /health    liveness probe
 *   GET  /scan?url= JSON scan API (needs ADMIN_KEY as a bearer token)
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      return json({
        ok: true,
        service: 'linkguard-bot',
        version: '1.0.0',
        checks: [
          'url-structure', 'punycode-homoglyph', 'brand-impersonation', 'tld-reputation',
          'dns-a-aaaa-mx-ns', 'rdap-domain-age', 'redirect-chain', 'http-headers',
          'html-forms', 'obfuscated-js', 'hidden-iframes', 'credential-harvesting',
          'urgency-copy', 'crypto-drainer', 'safe-browsing', 'virustotal', 'urlhaus',
          'cloudflare-malware-filter', 'browser-screenshot',
        ],
        kvBound: Boolean(env.CACHE),
        browserBound: Boolean(env.BROWSER),
        safeBrowsing: Boolean(env.SAFE_BROWSING_KEY),
        virusTotal: Boolean(env.VIRUSTOTAL_KEY),
      });
    }

    if (request.method === 'POST' && url.pathname === '/webhook') {
      if (env.WEBHOOK_SECRET) {
        const provided = request.headers.get('x-telegram-bot-api-secret-token');
        if (provided !== env.WEBHOOK_SECRET) {
          return new Response('unauthorized', { status: 401 });
        }
      }

      let update: TelegramUpdate;
      try {
        update = (await request.json()) as TelegramUpdate;
      } catch {
        return new Response('bad request', { status: 400 });
      }

      // Answer Telegram immediately; do the slow scan in the background so it
      // never retries a webhook we are already handling.
      ctx.waitUntil(handleUpdate(env, update));
      return new Response('ok', { status: 200 });
    }

    if (request.method === 'GET' && url.pathname === '/scan') {
      if (!env.ADMIN_KEY) {
        return json({ ok: false, error: 'The /scan API is disabled. Set ADMIN_KEY to enable it.' }, 403);
      }
      const auth = request.headers.get('authorization') ?? '';
      const token = auth.replace(/^Bearer\s+/i, '');
      if (token !== env.ADMIN_KEY) return json({ ok: false, error: 'unauthorized' }, 401);

      const target = url.searchParams.get('url');
      if (!target) return json({ ok: false, error: 'pass ?url=' }, 400);

      const result = await analyzeLink(env, target);
      const withReport = { ...result, report: buildReport(result) };
      const body = JSON.stringify(
        withReport,
        (key, value) => (key === 'bytes' ? `[${(value as Uint8Array).byteLength} bytes]` : value),
        2,
      );
      return new Response(body, { headers: { 'content-type': 'application/json; charset=utf-8' } });
    }

    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

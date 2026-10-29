import { USER_AGENT } from '../constants';
import type { Finding } from '../types';
import { fetchWithTimeout, readCapped, registrableDomain } from '../utils';

export interface RedirectHop {
  from: string;
  to: string;
  status: number;
}

export interface HttpResult {
  ok: boolean;
  status: number;
  finalUrl: string;
  redirects: RedirectHop[];
  headers: Record<string, string>;
  contentType: string;
  body: string;
  bodyBytes: number;
  truncated: boolean;
  elapsedMs: number;
  error: string | null;
  findings: Finding[];
}

const MAX_REDIRECTS = 6;
const MAX_BODY_BYTES = 400_000;

/**
 * Fetch the page the way a browser would, following redirects by hand so we
 * can see every hop, and cap the body so a hostile page cannot exhaust memory.
 */
export async function checkHttp(startUrl: string): Promise<HttpResult> {
  const started = Date.now();
  const redirects: RedirectHop[] = [];
  const findings: Finding[] = [];
  let current = startUrl;
  let response: Response | null = null;
  let error: string | null = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let res: Response;
    try {
      res = await fetchWithTimeout(
        current,
        {
          method: 'GET',
          redirect: 'manual',
          headers: {
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-IN,en;q=0.9,hi;q=0.8',
          },
        },
        12_000,
      );
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      break;
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        response = res;
        break;
      }
      const next = new URL(location, current).toString();
      redirects.push({ from: current, to: next, status: res.status });
      current = next;
      continue;
    }

    response = res;
    break;
  }

  if (!response) {
    return {
      ok: false,
      status: 0,
      finalUrl: current,
      redirects,
      headers: {},
      contentType: '',
      body: '',
      bodyBytes: 0,
      truncated: false,
      elapsedMs: Date.now() - started,
      error: error ?? 'Too many redirects',
      findings: [
        {
          id: 'http.unreachable',
          severity: 'medium',
          title: 'Website did not load',
          detail: error
            ? `The server refused or failed the connection (${error.slice(0, 120)}).`
            : `The link bounced through more than ${MAX_REDIRECTS} redirects and never landed.`,
          weight: 15,
        },
      ],
    };
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const contentType = headers['content-type'] ?? '';
  const isTextual = /text\/|json|xml|javascript/i.test(contentType) || contentType === '';
  let body = '';
  let bodyBytes = 0;
  let truncated = false;

  if (isTextual) {
    try {
      const capped = await readCapped(response, MAX_BODY_BYTES);
      body = capped.text;
      bodyBytes = capped.bytes;
      truncated = capped.truncated;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  }

  // --- redirect analysis -------------------------------------------------
  const startRegistrable = registrableDomain(new URL(startUrl).hostname);
  const finalRegistrable = registrableDomain(new URL(current).hostname);

  if (redirects.length > 0) {
    findings.push({
      id: 'http.redirects',
      severity: 'info',
      title: `${redirects.length} redirect${redirects.length === 1 ? '' : 's'}`,
      detail: redirects
        .slice(0, 3)
        .map((hop) => `${shortHost(hop.from)} → ${shortHost(hop.to)}`)
        .join(', '),
      weight: 0,
    });
  }

  if (redirects.length > 3) {
    findings.push({
      id: 'http.redirect-chain',
      severity: 'medium',
      title: 'Long redirect chain',
      detail: `${redirects.length} hops before the real page. Long chains are used to launder a bad link through reputable domains.`,
      weight: 14,
    });
  }

  if (startRegistrable !== finalRegistrable) {
    findings.push({
      id: 'http.cross-domain-redirect',
      severity: 'high',
      title: 'Redirects to a different domain',
      detail: `You asked for ${startRegistrable} but ended up on ${finalRegistrable}. Check that second domain carefully.`,
      weight: 20,
    });
  }

  // --- transport / response ---------------------------------------------
  if (new URL(current).protocol === 'http:') {
    findings.push({
      id: 'http.plain',
      severity: 'high',
      title: 'Final page is not encrypted',
      detail: 'The page you actually land on is served over HTTP with no encryption.',
      weight: 20,
    });
  }

  if (response.status >= 500) {
    findings.push({
      id: 'http.server-error',
      severity: 'medium',
      title: `Server error (${response.status})`,
      detail: 'The site is broken right now. A freshly taken-down scam page often looks exactly like this.',
      weight: 12,
    });
  } else if (response.status === 404 || response.status === 410) {
    findings.push({
      id: 'http.not-found',
      severity: 'low',
      title: `Page not found (${response.status})`,
      detail: 'The page does not exist anymore, or never did.',
      weight: 8,
    });
  } else if (response.status === 403 || response.status === 429) {
    findings.push({
      id: 'http.blocked-bot',
      severity: 'info',
      title: `Access limited (${response.status})`,
      detail: 'The site blocks automated visitors, so the page content could not be fully inspected. Treat the verdict as partial.',
      weight: 0,
    });
  }

  if (/application\/(x-)?(octet-stream|zip|x-msdownload|x-msdos-program|vnd\.android\.package-archive)/i.test(contentType)) {
    findings.push({
      id: 'http.binary-download',
      severity: 'high',
      title: 'The link is a file download, not a webpage',
      detail: `The server sends "${contentType}". Never install a file that arrived through a random link.`,
      weight: 30,
    });
  }

  const server = headers['server'] ?? '';
  if (/nginx|apache|cloudflare|gws|litespeed/i.test(server) === false && server.length > 0) {
    findings.push({
      id: 'http.odd-server',
      severity: 'low',
      title: 'Unusual server header',
      detail: `The server identifies itself as "${server.slice(0, 40)}", typical of a hastily set up host.`,
      weight: 4,
    });
  }

  // --- security headers (trust credits, not accusations) -----------------
  if (headers['strict-transport-security']) {
    findings.push({
      id: 'http.hsts',
      severity: 'good',
      title: 'HSTS enabled',
      detail: 'The site forces encrypted connections.',
      weight: -4,
    });
  }
  if (headers['content-security-policy']) {
    findings.push({
      id: 'http.csp',
      severity: 'good',
      title: 'Content Security Policy set',
      detail: 'The site restricts where scripts can load from - a sign of a maintained codebase.',
      weight: -3,
    });
  }

  return {
    ok: response.ok,
    status: response.status,
    finalUrl: current,
    redirects,
    headers,
    contentType,
    body,
    bodyBytes,
    truncated,
    elapsedMs: Date.now() - started,
    error,
    findings,
  };
}

function shortHost(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value.slice(0, 40);
  }
}

import { MULTI_LABEL_SUFFIXES } from './constants';

/** fetch with a hard timeout, so one slow host cannot stall the whole scan. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Read at most `maxBytes` of a response body, as text. */
export async function readCapped(res: Response, maxBytes: number): Promise<{ text: string; bytes: number; truncated: boolean }> {
  if (!res.body) return { text: '', bytes: 0, truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      chunks.push(value);
      total += value.byteLength;
    }
    if (total >= maxBytes) truncated = true;
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
  const merged = new Uint8Array(Math.min(total, maxBytes));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= merged.length) break;
    const slice = chunk.subarray(0, Math.min(chunk.byteLength, merged.length - offset));
    merged.set(slice, offset);
    offset += slice.byteLength;
  }
  return { text: new TextDecoder('utf-8').decode(merged), bytes: merged.length, truncated };
}

/** Extract the first URL-looking thing from a free-text message. */
export function extractUrl(text: string): string | null {
  const trimmed = text.trim();
  const withScheme = trimmed.match(/https?:\/\/[^\s<>"']+/i);
  if (withScheme) return stripTrailingPunctuation(withScheme[0]);

  // "example.com/login" style without a scheme.
  const bare = trimmed.match(/\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})(\/[^\s<>"']*)?/i);
  if (bare) {
    const candidate = stripTrailingPunctuation(bare[0]);
    // Reject things that are clearly not domains (file names, version numbers).
    if (/\.[a-z]{2,24}$/i.test(candidate.split('/')[0]) && !/^\d/.test(candidate)) {
      return `https://${candidate}`;
    }
  }
  return null;
}

function stripTrailingPunctuation(value: string): string {
  return value.replace(/[.,;:!?)\]}'"]+$/g, '');
}

/** Registrable domain (eTLD+1) using a small public-suffix list. */
export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

export function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') || /^\[/.test(hostname);
}

export function isIpOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    isIpLiteral(host) ||
    host === 'localhost' ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.localhost') ||
    host === '0.0.0.0' ||
    host === '127.0.0.1'
  );
}

/** Decode punycode labels so we can show "аpple.com" instead of xn--... */
export function decodeHostname(hostname: string): string {
  return hostname
    .split('.')
    .map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label;
      try {
        return punycodeDecode(label.slice(4).toLowerCase());
      } catch {
        return label;
      }
    })
    .join('.');
}

/** RFC 3492 punycode decoder (no dependencies, works on Workers). */
export function punycodeDecode(input: string): string {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    let d = firstTime ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((base - tMin) * tMax) >> 1) {
      d = Math.floor(d / (base - tMin));
      k += base;
    }
    return Math.floor(k + ((base - tMin + 1) * d) / (d + skew));
  };

  const digitToValue = (code: number): number => {
    if (code >= 0x30 && code <= 0x39) return code - 22; // 0-9 -> 26..35
    if (code >= 0x41 && code <= 0x5a) return code - 0x41; // A-Z -> 0..25
    if (code >= 0x61 && code <= 0x7a) return code - 0x61; // a-z -> 0..25
    return base;
  };

  const output: number[] = [];
  const lastDash = input.lastIndexOf('-');
  const basicLength = lastDash > 0 ? lastDash : 0;
  for (let i = 0; i < basicLength; i++) output.push(input.charCodeAt(i));

  let index = basicLength > 0 ? lastDash + 1 : 0;
  let n = initialN;
  let bias = initialBias;
  let i = 0;

  while (index < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (index >= input.length) throw new Error('punycode: truncated input');
      const digit = digitToValue(input.charCodeAt(index++));
      if (digit >= base) throw new Error('punycode: bad digit');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldI, length, oldI === 0);
    n += Math.floor(i / length);
    i = i % length;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

/** Count non-overlapping regex hits, capped so a huge page cannot blow up. */
export function countMatches(text: string, regex: RegExp, cap = 50): number {
  const global = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  let count = 0;
  let match: RegExpExecArray | null;
  while (count < cap && (match = global.exec(text)) !== null) {
    count++;
    if (match.index === global.lastIndex) global.lastIndex++;
  }
  return count;
}

/** Strip tags/scripts so text heuristics look at visible copy only. */
export function visibleText(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : plural ?? `${singular}s`}`;
}

export function formatAge(days: number | null): string {
  if (days === null) return 'unknown';
  if (days < 1) return 'less than a day';
  if (days < 60) return `${days} days`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  const years = days / 365;
  return `${years.toFixed(years < 10 ? 1 : 0)} years`;
}

export function sha256Short(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  return crypto.subtle.digest('SHA-256', data).then((buf) =>
    Array.from(new Uint8Array(buf))
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  );
}

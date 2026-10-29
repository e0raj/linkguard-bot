import type { Env, ScreenshotResult } from '../types';
import { fetchWithTimeout } from '../utils';

const MAX_SHOT_BYTES = 4_500_000;

/**
 * Capture what the visitor would actually see.
 *
 * 1. Cloudflare Browser Rendering (real Chromium, needs the BROWSER binding).
 * 2. Free third-party renderers, only if SCREENSHOT_FALLBACK is "on".
 *
 * A screenshot is evidence for the human, not a security control, so failing
 * to get one never fails the scan.
 */
export async function captureScreenshot(env: Env, url: string): Promise<ScreenshotResult | null> {
  const viaBrowser = await viaBrowserRendering(env, url);
  if (viaBrowser) return viaBrowser;

  if ((env.SCREENSHOT_FALLBACK ?? 'on').toLowerCase() === 'off') return null;

  const viaMshots = await viaThirdParty(
    `https://s.wordpress.com/mshots/v1/${encodeURIComponent(url)}?w=1280&h=900`,
  );
  if (viaMshots) return viaMshots;

  const viaThum = await viaThirdParty(
    `https://image.thum.io/get/width/1280/crop/900/noanimate/${url}`,
  );
  if (viaThum) return viaThum;

  return null;
}

async function viaBrowserRendering(env: Env, url: string): Promise<ScreenshotResult | null> {
  if (!env.BROWSER) return null;
  try {
    const puppeteer = (await import('@cloudflare/puppeteer')).default;
    const browser = await puppeteer.launch(env.BROWSER);
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      );
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 25_000 });
      // Give late-loading overlays a moment, then shoot the visible viewport.
      await new Promise((resolve) => setTimeout(resolve, 1200));
      const shot = (await page.screenshot({ type: 'jpeg', quality: 72, fullPage: false })) as Uint8Array;
      if (!shot || shot.byteLength < 2_000) {
        return { bytes: new Uint8Array(), contentType: 'image/jpeg', source: 'none', note: 'Page rendered blank' };
      }
      return { bytes: shot, contentType: 'image/jpeg', source: 'browser-rendering' };
    } finally {
      await browser.close();
    }
  } catch (err) {
    return {
      bytes: new Uint8Array(),
      contentType: 'image/jpeg',
      source: 'none',
      note: err instanceof Error ? err.message.slice(0, 160) : 'browser rendering failed',
    };
  }
}

async function viaThirdParty(endpoint: string): Promise<ScreenshotResult | null> {
  try {
    const res = await fetchWithTimeout(endpoint, { headers: { accept: 'image/*' } }, 20_000);
    if (!res.ok) return null;
    const contentType = res.headers.get('content-type') ?? '';
    if (!contentType.startsWith('image/')) return null;
    const buffer = await res.arrayBuffer();
    if (buffer.byteLength < 2_000 || buffer.byteLength > MAX_SHOT_BYTES) return null;
    return { bytes: new Uint8Array(buffer), contentType, source: 'fallback' };
  } catch {
    return null;
  }
}

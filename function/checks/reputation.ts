import type { Env, Finding, ReputationResult } from '../types';
import { fetchWithTimeout } from '../utils';
import { checkCloudflareFilter } from './dns';

/**
 * Third-party reputation feeds. All optional - each one degrades to "skipped"
 * when its key is missing, and the scan still produces a verdict.
 */
export async function checkReputation(env: Env, url: string, host: string): Promise<{ result: ReputationResult; findings: Finding[] }> {
  const result: ReputationResult = {
    safeBrowsing: 'skipped',
    safeBrowsingThreats: [],
    virusTotal: 'skipped',
    virusTotalPositives: 0,
    virusTotalEngines: 0,
    urlhaus: 'skipped',
    cloudflareFilter: 'skipped',
  };
  const findings: Finding[] = [];

  const [safeBrowsing, virusTotal, urlhaus, cloudflare] = await Promise.all([
    lookupSafeBrowsing(env, url),
    lookupVirusTotal(env, url),
    lookupUrlhaus(url),
    checkCloudflareFilter(host),
  ]);

  result.safeBrowsing = safeBrowsing.status;
  result.safeBrowsingThreats = safeBrowsing.threats;
  result.virusTotal = virusTotal.status;
  result.virusTotalPositives = virusTotal.positives;
  result.virusTotalEngines = virusTotal.engines;
  result.urlhaus = urlhaus;
  result.cloudflareFilter = cloudflare;

  if (safeBrowsing.status === 'threat') {
    findings.push({
      id: 'rep.safe-browsing',
      severity: 'critical',
      title: 'Flagged by Google Safe Browsing',
      detail: `Google lists this URL as ${safeBrowsing.threats.join(', ') || 'unsafe'}. Do not open it.`,
      weight: 65,
    });
  }

  if (virusTotal.status === 'threat') {
    findings.push({
      id: 'rep.virustotal',
      severity: 'critical',
      title: `Detected by ${virusTotal.positives} security engines`,
      detail: `VirusTotal shows ${virusTotal.positives} of ${virusTotal.engines} vendors flagging this link as malicious.`,
      weight: 55,
    });
  }

  if (urlhaus === 'threat') {
    findings.push({
      id: 'rep.urlhaus',
      severity: 'critical',
      title: 'Listed in URLhaus malware feed',
      detail: 'This exact URL is a known malware distribution link in abuse.ch URLhaus.',
      weight: 60,
    });
  }

  if (cloudflare === 'blocked') {
    findings.push({
      id: 'rep.cloudflare-filter',
      severity: 'high',
      title: 'Blocked by Cloudflare malware filter',
      detail: "Cloudflare's 1.1.1.2 malware-blocking resolver refuses to resolve this domain, which means it already appears in their threat feed.",
      weight: 35,
    });
  }

  if (
    safeBrowsing.status === 'clean' &&
    urlhaus === 'clean' &&
    cloudflare === 'clean'
  ) {
    findings.push({
      id: 'rep.clean-feeds',
      severity: 'good',
      title: 'Not in any threat feed',
      detail: 'Clean in Google Safe Browsing, URLhaus and the Cloudflare malware feed.',
      weight: -14,
    });
  }

  return { result, findings };
}

async function lookupSafeBrowsing(env: Env, url: string): Promise<{ status: ReputationResult['safeBrowsing']; threats: string[] }> {
  if (!env.SAFE_BROWSING_KEY) return { status: 'skipped', threats: [] };
  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.SAFE_BROWSING_KEY)}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'linkguard-bot', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      },
      9000,
    );
    if (!res.ok) return { status: 'error', threats: [] };
    const data = (await res.json()) as { matches?: { threatType?: string }[] };
    if (data.matches && data.matches.length > 0) {
      return {
        status: 'threat',
        threats: Array.from(new Set(data.matches.map((m) => (m.threatType ?? 'UNKNOWN').toLowerCase()))),
      };
    }
    return { status: 'clean', threats: [] };
  } catch {
    return { status: 'error', threats: [] };
  }
}

async function lookupVirusTotal(env: Env, url: string): Promise<{ status: ReputationResult['virusTotal']; positives: number; engines: number }> {
  if (!env.VIRUSTOTAL_KEY) return { status: 'skipped', positives: 0, engines: 0 };
  try {
    const id = base64Url(url);
    const res = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/urls/${id}`,
      { headers: { 'x-apikey': env.VIRUSTOTAL_KEY } },
      9000,
    );
    if (res.status === 404) return { status: 'unknown', positives: 0, engines: 0 };
    if (!res.ok) return { status: 'error', positives: 0, engines: 0 };
    const data = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number } } };
    };
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) return { status: 'unknown', positives: 0, engines: 0 };
    const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    const engines = positives + (stats.harmless ?? 0) + (stats.undetected ?? 0);
    return { status: positives > 0 ? 'threat' : 'clean', positives, engines };
  } catch {
    return { status: 'error', positives: 0, engines: 0 };
  }
}

async function lookupUrlhaus(url: string): Promise<ReputationResult['urlhaus']> {
  try {
    const body = new URLSearchParams({ url });
    const res = await fetchWithTimeout(
      'https://urlhaus-api.abuse.ch/v1/url/',
      { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: body.toString() },
      8000,
    );
    if (!res.ok) return 'error';
    const data = (await res.json()) as { query_status?: string };
    if (data.query_status === 'ok') return 'threat';
    if (data.query_status === 'no_results') return 'clean';
    return 'skipped';
  } catch {
    return 'error';
  }
}

function base64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

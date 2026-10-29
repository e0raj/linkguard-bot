import type { Env, Finding, ScanResult } from './types';
import { scoreFindings } from './scoring';
import { analyzeUrl } from './checks/url';
import { checkDns } from './checks/dns';
import { checkRdap } from './checks/rdap';
import { checkHttp } from './checks/http';
import { analyzeContent } from './checks/content';
import { checkReputation } from './checks/reputation';
import { captureScreenshot } from './checks/screenshot';
import { isIpOrLocalHost, registrableDomain } from './utils';

/**
 * The whole scan, end to end.
 *
 * Everything that does not depend on the final page runs in parallel, then the
 * page is fetched, its HTML inspected, and a screenshot taken. Each stage
 * contributes findings; scoring happens once at the end so a single critical
 * signal cannot be diluted by clean ones.
 */
export async function analyzeLink(env: Env, rawUrl: string): Promise<ScanResult> {
  const started = Date.now();

  const urlInfo = analyzeUrl(rawUrl);
  const findings: Finding[] = [...urlInfo.findings];

  if (!urlInfo.host) {
    const scored = scoreFindings(findings);
    return {
      verdict: 'unknown',
      score: scored.score,
      headline: 'That does not look like a web address. Send me something like example.com.',
      findings,
      meta: emptyMeta(rawUrl, started),
    };
  }

  if (isIpOrLocalHost(urlInfo.host)) {
    findings.push({
      id: 'safety.private-target',
      severity: 'high',
      title: 'Points to a private or raw address',
      detail: 'I do not open internal, localhost or bare-IP targets. That pattern is used to probe networks.',
      weight: 30,
    });
    const scored = scoreFindings(findings);
    return {
      verdict: 'danger',
      score: scored.score,
      headline: 'I will not open private network addresses.',
      findings,
      meta: emptyMeta(rawUrl, started),
    };
  }

  // --- stage 1: domain + reputation, in parallel ------------------------
  const [dns, rdap, reputation] = await Promise.all([
    checkDns(urlInfo.host),
    checkRdap(urlInfo.registrable),
    checkReputation(env, urlInfo.normalized, urlInfo.host),
  ]);
  findings.push(...dns.findings, ...rdap.findings, ...reputation.findings);

  // --- stage 2: fetch the page -----------------------------------------
  const http = await checkHttp(urlInfo.normalized);
  findings.push(...http.findings);

  let finalHost = urlInfo.host;
  let finalUnicode = urlInfo.unicodeHost;
  let finalRegistrable = urlInfo.registrable;
  let title = '';
  let description = '';
  let pageBytes = http.bodyBytes;

  try {
    const finalUrl = new URL(http.finalUrl);
    finalHost = finalUrl.hostname.toLowerCase();
    finalRegistrable = registrableDomain(finalHost);
    if (finalRegistrable !== urlInfo.registrable) {
      const finalRdap = await checkRdap(finalRegistrable);
      findings.push(...finalRdap.findings.map((f) => ({ ...f, id: `${f.id}.final` })));
    }
  } catch {
    // keep the original host
  }

  // --- stage 3: page content -------------------------------------------
  if (http.body) {
    const content = analyzeContent(http.body, http.finalUrl, http.contentType);
    findings.push(...content.findings);
    title = content.title;
    description = content.description;
  } else if (http.error) {
    findings.push({
      id: 'content.no-body',
      severity: 'info',
      title: 'Page content could not be read',
      detail: 'The verdict is based on the domain, DNS, whois and reputation data only.',
      weight: 0,
    });
  }

  // --- stage 4: screenshot ---------------------------------------------
  const screenshot = await captureScreenshot(env, http.finalUrl);
  if (!screenshot) {
    findings.push({
      id: 'shot.unavailable',
      severity: 'info',
      title: 'No screenshot',
      detail: 'The page could not be rendered, so there is no visual evidence with this report.',
      weight: 0,
    });
  } else if (screenshot.source === 'none') {
    findings.push({
      id: 'shot.blank',
      severity: 'low',
      title: 'Page renders blank',
      detail: 'The browser loaded the page but drew nothing. Some scam pages show content only to specific visitors.',
      weight: 8,
    });
  }

  const scored = scoreFindings(findings);

  return {
    verdict: scored.verdict,
    score: scored.score,
    headline: scored.headline,
    findings,
    meta: {
      inputUrl: rawUrl,
      finalUrl: http.finalUrl,
      host: finalHost,
      unicodeHost: finalUnicode,
      registrableDomain: finalRegistrable,
      scheme: http.finalUrl.startsWith('https:') ? 'https' : 'http',
      statusCode: http.status,
      redirectCount: http.redirects.length,
      contentType: http.contentType,
      title,
      description,
      domainAgeDays: rdap.domainAgeDays,
      registrar: rdap.registrar,
      expiresInDays: rdap.expiresInDays,
      hasA: dns.hasA,
      hasMx: dns.hasMx,
      nameservers: dns.nameservers,
      hsts: Boolean(http.headers['strict-transport-security']),
      csp: Boolean(http.headers['content-security-policy']),
      serverHeader: http.headers['server'] ?? '',
      pageBytes,
      screenshot,
      reputation: reputation.result,
      elapsedMs: Date.now() - started,
      checkedAt: new Date().toISOString(),
    },
  };
}

function emptyMeta(rawUrl: string, started: number): ScanResult['meta'] {
  return {
    inputUrl: rawUrl,
    finalUrl: rawUrl,
    host: '',
    unicodeHost: '',
    registrableDomain: '',
    scheme: '',
    statusCode: 0,
    redirectCount: 0,
    contentType: '',
    title: '',
    description: '',
    domainAgeDays: null,
    registrar: null,
    expiresInDays: null,
    hasA: false,
    hasMx: false,
    nameservers: [],
    hsts: false,
    csp: false,
    serverHeader: '',
    pageBytes: 0,
    screenshot: null,
    reputation: {
      safeBrowsing: 'skipped',
      safeBrowsingThreats: [],
      virusTotal: 'skipped',
      virusTotalPositives: 0,
      virusTotalEngines: 0,
      urlhaus: 'skipped',
      cloudflareFilter: 'skipped',
    },
    elapsedMs: Date.now() - started,
    checkedAt: new Date().toISOString(),
  };
}

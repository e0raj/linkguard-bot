import type { ScanResult } from './types';
import { severityIcon, verdictBadge } from './scoring';
import { escapeHtml, formatAge, truncate } from './utils';

const MAX_MESSAGE = 3800;

/** Build the Telegram HTML report. Kept under the 4096 char message limit. */
export function buildReport(result: ScanResult): string {
  const { meta, score, verdict, findings } = result;
  const lines: string[] = [];

  lines.push(`<b>${verdictBadge(verdict)}</b>  ·  risk score <b>${score}/100</b>`);
  lines.push(`<i>${escapeHtml(result.headline)}</i>`);
  lines.push('');

  lines.push(`<b>Domain</b>  <code>${escapeHtml(meta.registrableDomain || meta.host || 'unknown')}</code>`);
  if (meta.unicodeHost && meta.unicodeHost !== meta.host) {
    lines.push(`<b>Real spelling</b>  <code>${escapeHtml(meta.unicodeHost)}</code>`);
  }
  if (meta.title) lines.push(`<b>Page title</b>  ${escapeHtml(truncate(meta.title, 90))}`);
  lines.push(
    `<b>Domain age</b>  ${formatAge(meta.domainAgeDays)}` +
      (meta.registrar ? `  ·  ${escapeHtml(truncate(meta.registrar, 40))}` : ''),
  );
  lines.push(
    `<b>Transport</b>  ${meta.scheme === 'https' ? 'HTTPS ✅' : 'HTTP (unencrypted) ⛔'}` +
      (meta.statusCode ? `  ·  HTTP ${meta.statusCode}` : ''),
  );
  lines.push(`<b>Redirects</b>  ${meta.redirectCount}` + (meta.pageBytes ? `  ·  ${Math.round(meta.pageBytes / 1024)} KB page` : ''));
  lines.push('');

  const rep = meta.reputation;
  const feeds: string[] = [];
  feeds.push(`Safe Browsing: ${label(rep.safeBrowsing)}`);
  if (rep.virusTotal !== 'skipped') feeds.push(`VirusTotal: ${label(rep.virusTotal)}${rep.virusTotalEngines ? ` (${rep.virusTotalPositives}/${rep.virusTotalEngines})` : ''}`);
  if (rep.urlhaus !== 'skipped') feeds.push(`URLhaus: ${label(rep.urlhaus)}`);
  if (rep.cloudflareFilter !== 'skipped') feeds.push(`CF filter: ${label(rep.cloudflareFilter)}`);
  lines.push(`<b>Threat feeds</b>  ${feeds.join(' · ')}`);
  lines.push('');

  const notable = findings
    .filter((f) => f.severity !== 'good' && f.severity !== 'info')
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 6);

  if (notable.length > 0) {
    lines.push('<b>What I found</b>');
    for (const finding of notable) {
      lines.push(`${severityIcon(finding.severity)} <b>${escapeHtml(finding.title)}</b> — ${escapeHtml(truncate(finding.detail, 180))}`);
    }
  } else {
    lines.push('<b>What I found</b>');
    lines.push('🟢 Nothing suspicious in the URL, DNS records, whois data, page source or threat feeds.');
  }

  const positives = findings.filter((f) => f.severity === 'good').slice(0, 3);
  if (positives.length > 0) {
    lines.push('');
    lines.push('<b>Good signs</b>');
    for (const finding of positives) {
      lines.push(`🟢 ${escapeHtml(finding.title)} — ${escapeHtml(truncate(finding.detail, 120))}`);
    }
  }

  lines.push('');
  lines.push(
    `<i>Scanned in ${(meta.elapsedMs / 1000).toFixed(1)}s · ${meta.screenshot?.source === 'none' ? 'no screenshot' : 'screenshot attached'} · LinkGuard is automated advice, not a guarantee.</i>`,
  );

  let text = lines.join('\n');
  if (text.length > MAX_MESSAGE) text = `${text.slice(0, MAX_MESSAGE - 20)}\n<i>…report trimmed</i>`;
  return text;
}

export function buildScreenshotCaption(result: ScanResult): string {
  const verdict = verdictBadge(result.verdict);
  const title = result.meta.title ? truncate(result.meta.title, 60) : result.meta.registrableDomain;
  const source =
    result.meta.screenshot?.source === 'browser-rendering'
      ? 'live Chromium render'
      : result.meta.screenshot?.source === 'fallback'
        ? 'third-party render'
        : 'no screenshot';
  return `${verdict} · ${escapeHtml(title)}\n<i>${escapeHtml(source)}</i>`;
}

export function buildProgressMessage(url: string, step: string): string {
  return `🔍 <b>Scanning</b> <code>${escapeHtml(truncate(url, 80))}</code>\n\n${step}`;
}

function label(value: string): string {
  switch (value) {
    case 'clean': return 'clean ✅';
    case 'threat': return 'THREAT ⛔';
    case 'skipped': return 'not checked';
    case 'unknown': return 'no data';
    default: return 'error';
  }
}

import { DANGER_THRESHOLD, SAFE_THRESHOLD } from './constants';
import type { Finding, Severity, VerdictLevel } from './types';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  good: 5,
};

export interface ScoreBreakdown {
  score: number;
  verdict: VerdictLevel;
  headline: string;
  counts: Record<Severity, number>;
  topFindings: Finding[];
}

/**
 * Turn a pile of findings into one number the user can act on.
 *
 * Weights are additive, trust credits are negative, and the result is clamped
 * to 0-100. A single critical finding can never be averaged away by a hundred
 * "looks fine" signals: any critical finding forces at least the caution band.
 */
export function scoreFindings(findings: Finding[]): ScoreBreakdown {
  const unique = dedupe(findings);
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, good: 0 };
  let raw = 0;

  for (const finding of unique) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    raw += finding.weight;
  }

  let score = Math.max(0, Math.min(100, Math.round(raw)));

  // A critical finding is a hard floor: never call something "safe" that
  // asked for an OTP or posts passwords to another domain.
  if (counts.critical > 0) score = Math.max(score, DANGER_THRESHOLD + 5);
  else if (counts.high >= 2) score = Math.max(score, SAFE_THRESHOLD + 8);

  const verdict: VerdictLevel =
    score <= SAFE_THRESHOLD ? 'safe' : score <= DANGER_THRESHOLD ? 'caution' : 'danger';

  return {
    score,
    verdict,
    headline: headlineFor(verdict, counts),
    counts,
    topFindings: unique
      .filter((f) => f.severity !== 'good' && f.severity !== 'info')
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.weight - a.weight)
      .slice(0, 6),
  };
}

function headlineFor(verdict: VerdictLevel, counts: Record<Severity, number>): string {
  if (verdict === 'danger') {
    if (counts.critical > 0) return 'Do not open this link, and never type anything into it.';
    return 'This link looks malicious. Avoid it.';
  }
  if (verdict === 'caution') return 'Be careful. Several things here look off.';
  if (verdict === 'safe') return 'No red flags found. Still check the domain name before you log in.';
  return 'Could not fully check this link.';
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = seen.get(finding.id);
    if (!existing || Math.abs(finding.weight) > Math.abs(existing.weight)) {
      seen.set(finding.id, finding);
    }
  }
  return Array.from(seen.values());
}

export function severityIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return '⛔';
    case 'high': return '🔴';
    case 'medium': return '🟠';
    case 'low': return '🟡';
    case 'good': return '🟢';
    default: return 'ℹ️';
  }
}

export function verdictBadge(verdict: VerdictLevel): string {
  switch (verdict) {
    case 'safe': return '✅ SAFE';
    case 'caution': return '⚠️ SUSPICIOUS';
    case 'danger': return '⛔ DANGEROUS';
    default: return '❔ UNKNOWN';
  }
}

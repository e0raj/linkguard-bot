import {
  HIGH_RISK_TLDS,
  MEDIUM_RISK_TLDS,
  PHISHY_HOST_WORDS,
  PROTECTED_BRANDS,
  TRUSTED_TLDS,
  URL_SHORTENERS,
  FREE_HOSTING_SUFFIXES,
  DANGEROUS_EXTENSIONS,
} from '../constants';
import type { Finding } from '../types';
import { decodeHostname, isIpLiteral, registrableDomain } from '../utils';

export interface UrlAnalysis {
  normalized: string;
  host: string;
  unicodeHost: string;
  registrable: string;
  tld: string;
  scheme: string;
  findings: Finding[];
  isShortener: boolean;
  isTrustedTld: boolean;
}

/** Pure, offline analysis of the URL string itself. */
export function analyzeUrl(rawInput: string): UrlAnalysis {
  const findings: Finding[] = [];
  let normalized = rawInput.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) normalized = `https://${normalized}`;

  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    return {
      normalized: rawInput,
      host: '',
      unicodeHost: '',
      registrable: '',
      tld: '',
      scheme: '',
      isShortener: false,
      isTrustedTld: false,
      findings: [
        {
          id: 'url.invalid',
          severity: 'critical',
          title: 'Not a valid URL',
          detail: 'The text could not be parsed as a web address.',
          weight: 60,
        },
      ],
    };
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const unicodeHost = decodeHostname(host);
  const registrable = registrableDomain(host);
  const labels = host.split('.');
  const tld = labels.slice(-1)[0] ?? '';
  const twoLabelTld = labels.slice(-2).join('.');
  const isTrustedTld = TRUSTED_TLDS.includes(twoLabelTld) || TRUSTED_TLDS.includes(tld);
  const isShortener = URL_SHORTENERS.some((s) => host === s || host.endsWith(`.${s}`));

  // --- scheme / transport -------------------------------------------------
  if (url.protocol === 'http:') {
    findings.push({
      id: 'url.no-https',
      severity: 'high',
      title: 'No HTTPS',
      detail: 'The page is served over plain HTTP, so anything you type can be read in transit.',
      weight: 22,
    });
  } else if (url.protocol !== 'https:') {
    findings.push({
      id: 'url.weird-scheme',
      severity: 'high',
      title: `Unusual scheme (${url.protocol.replace(':', '')})`,
      detail: 'This is not a normal web link. Do not open it.',
      weight: 45,
    });
  }

  // --- credentials embedded in the URL ------------------------------------
  if (url.username || url.password) {
    findings.push({
      id: 'url.credentials',
      severity: 'critical',
      title: 'Fake login details inside the link',
      detail: `The link carries "${url.username}@…" before the real host. A classic trick to make a bad domain look trustworthy.`,
      weight: 40,
    });
  }

  // --- IP literal / local targets ----------------------------------------
  if (isIpLiteral(host)) {
    findings.push({
      id: 'url.ip-host',
      severity: 'high',
      title: 'Raw IP address instead of a domain',
      detail: 'Real services use a name like example.com, not a bare IP.',
      weight: 28,
    });
  }

  // --- punycode / homoglyph ----------------------------------------------
  if (host.includes('xn--')) {
    const looksLatin = /^[\x00-\x7F]+$/.test(unicodeHost) === false;
    findings.push({
      id: 'url.punycode',
      severity: 'high',
      title: 'Lookalike characters in the domain',
      detail: `The domain is really "${unicodeHost}" - non-Latin letters that look like English ones. This is a homoglyph trick.`,
      weight: looksLatin ? 35 : 20,
    });
  }

  // --- zero width / invisible characters ---------------------------------
  if (/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(rawInput)) {
    findings.push({
      id: 'url.invisible-chars',
      severity: 'high',
      title: 'Invisible characters in the link',
      detail: 'The link contains hidden Unicode characters used to disguise its real destination.',
      weight: 30,
    });
  }

  // --- TLD reputation ----------------------------------------------------
  if (HIGH_RISK_TLDS.includes(tld)) {
    findings.push({
      id: 'url.bad-tld',
      severity: 'medium',
      title: `High-abuse domain ending (.${tld})`,
      detail: `".${tld}" is free or nearly free to register and is used in a large share of phishing campaigns.`,
      weight: 18,
    });
  } else if (MEDIUM_RISK_TLDS.includes(tld)) {
    findings.push({
      id: 'url.cheap-tld',
      severity: 'low',
      title: `Cheap domain ending (.${tld})`,
      detail: `".${tld}" is cheap to register, so it shows up often in throwaway scam sites. Not damning on its own.`,
      weight: 7,
    });
  }

  // --- structure ---------------------------------------------------------
  if (labels.length > 4) {
    findings.push({
      id: 'url.many-subdomains',
      severity: 'medium',
      title: `${labels.length} levels of subdomain`,
      detail: `"${host}" stacks subdomains to bury the real domain (${registrable}).`,
      weight: 14,
    });
  }

  if (host.length > 45) {
    findings.push({
      id: 'url.long-host',
      severity: 'low',
      title: 'Very long domain name',
      detail: `${host.length} characters. Long hosts are used to push the real domain out of view on mobile.`,
      weight: 8,
    });
  }

  if (normalized.length > 150) {
    findings.push({
      id: 'url.long-url',
      severity: 'low',
      title: 'Very long URL',
      detail: `${normalized.length} characters - hard to read, easy to hide things in.`,
      weight: 6,
    });
  }

  if (url.port && !['80', '443', ''].includes(url.port)) {
    findings.push({
      id: 'url.odd-port',
      severity: 'medium',
      title: `Unusual port (:${url.port})`,
      detail: 'Normal websites run on 443. A random port usually means a throwaway server.',
      weight: 12,
    });
  }

  // --- brand impersonation ----------------------------------------------
  if (!isTrustedTld) {
    const registrableLabel = registrable.split('.')[0] ?? '';
    for (const brand of PROTECTED_BRANDS) {
      const inPlainHost = containsBrand(host, brand);
      const inDecodedHost = unicodeHost !== host && containsBrand(unicodeHost, brand);
      if (!inPlainHost && !inDecodedHost) continue;
      if (registrableLabel === brand || registrableLabel.startsWith(brand)) continue;
      const homoglyph = !inPlainHost && inDecodedHost;
      findings.push({
        id: `url.brand-${brand}`,
        severity: 'critical',
        title: `Pretends to be ${capitalize(brand)}`,
        detail: homoglyph
          ? `The domain "${unicodeHost}" imitates ${capitalize(brand)} using lookalike letters, but the real domain is ${registrable}.`
          : `"${host}" mentions ${capitalize(brand)} but is registered to ${registrable}, which ${capitalize(brand)} does not own.`,
        weight: homoglyph ? 45 : 32,
      });
      break;
    }
  }

  // --- phishing words in the hostname ------------------------------------
  const phishyHits = PHISHY_HOST_WORDS.filter((word) => host.split(/[.\-_]/).includes(word));
  if (phishyHits.length > 0 && !isTrustedTld) {
    findings.push({
      id: 'url.phishy-host-words',
      severity: 'medium',
      title: 'Login-style wording in the domain',
      detail: `The hostname contains ${phishyHits.slice(0, 3).map((w) => `"${w}"`).join(', ')}. Genuine banks put that in the path, not the domain.`,
      weight: 12 + Math.min(8, phishyHits.length * 2),
    });
  }

  // --- free hosting ------------------------------------------------------
  const freeHost = FREE_HOSTING_SUFFIXES.find((suffix) => host === suffix || host.endsWith(`.${suffix}`));
  if (freeHost) {
    findings.push({
      id: 'url.free-hosting',
      severity: 'low',
      title: 'Free / shared hosting',
      detail: `Hosted on ${freeHost}, where anyone can publish in minutes with no identity check.`,
      weight: 9,
    });
  }

  // --- shortener ---------------------------------------------------------
  if (isShortener) {
    findings.push({
      id: 'url.shortener',
      severity: 'info',
      title: 'Shortened link',
      detail: `The real destination is hidden behind ${host}. The scan follows the redirect and checks the final page.`,
      weight: 0,
    });
  }

  // --- dangerous file ----------------------------------------------------
  const pathLower = url.pathname.toLowerCase();
  const dangerousExt = DANGEROUS_EXTENSIONS.find((ext) => pathLower.endsWith(ext));
  if (dangerousExt) {
    findings.push({
      id: 'url.dangerous-file',
      severity: 'high',
      title: `Direct download of ${dangerousExt} file`,
      detail: 'This link downloads an installable file. That is how most Android banking trojans spread in India.',
      weight: 30,
    });
  } else if (/\.(apk|exe)(\?|$)/i.test(url.search)) {
    findings.push({
      id: 'url.dangerous-file-query',
      severity: 'medium',
      title: 'Download parameter in the link',
      detail: 'The link appears to trigger a file download.',
      weight: 14,
    });
  }

  // --- encoding tricks ---------------------------------------------------
  const encodedDots = (url.pathname.match(/%2e/gi) ?? []).length;
  const encodedSlashes = (url.pathname.match(/%2f/gi) ?? []).length;
  if (encodedDots > 0 || encodedSlashes > 1) {
    findings.push({
      id: 'url.encoded-path',
      severity: 'medium',
      title: 'Encoded characters in the path',
      detail: 'The URL hides dots or slashes in percent-encoding, which is used to slip past filters.',
      weight: 12,
    });
  }

  // --- trust credits -----------------------------------------------------
  if (isTrustedTld) {
    findings.push({
      id: 'url.trusted-tld',
      severity: 'good',
      title: 'Government / education domain',
      detail: `".${twoLabelTld}" domains are restricted to verified institutions.`,
      weight: -15,
    });
  }

  return {
    normalized,
    host,
    unicodeHost,
    registrable,
    tld,
    scheme: url.protocol.replace(':', ''),
    findings,
    isShortener,
    isTrustedTld,
  };
}

function containsBrand(host: string, brand: string): boolean {
  if (brand.length <= 3) {
    // Short brands (sbi, jio, vi, upi) must be a whole label to avoid noise.
    return host.split(/[.\-_]/).includes(brand);
  }
  return host.includes(brand);
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

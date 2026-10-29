import {
  CREDENTIAL_THEFT_PATTERNS,
  OBFUSCATION_PATTERNS,
  URGENCY_PATTERNS,
  WALLET_ADDRESS_REGEX,
} from '../constants';
import type { Finding } from '../types';
import { countMatches, registrableDomain, truncate, visibleText } from '../utils';

export interface ContentResult {
  title: string;
  description: string;
  findings: Finding[];
  textLength: number;
  passwordFields: number;
  formCount: number;
  iframeCount: number;
  externalScriptHosts: number;
  parked: boolean;
}

/**
 * Inspect the fetched HTML: forms, scripts, hidden elements, social-engineering
 * copy. Everything here is string analysis - no JS from the page is executed.
 */
export function analyzeContent(html: string, pageUrl: string, contentType: string): ContentResult {
  const findings: Finding[] = [];
  const title = truncate(extractTitle(html), 120);
  const description = truncate(extractMetaDescription(html), 200);
  const text = visibleText(html);
  const lowerHtml = html.toLowerCase();

  const pageHost = safeHost(pageUrl);
  const pageRegistrable = pageHost ? registrableDomain(pageHost) : '';

  if (text.length < 40 && /text\/html/i.test(contentType || 'text/html')) {
    findings.push({
      id: 'content.empty',
      severity: 'low',
      title: 'Almost no readable content',
      detail: 'The page renders little or nothing. Scam pages often hide content until a specific device or country visits.',
      weight: 8,
    });
  }

  // --- password / login forms -------------------------------------------
  const passwordFields = (html.match(/<input\b[^>]*type\s*=\s*["']?password/gi) ?? []).length;
  const formCount = (html.match(/<form\b/gi) ?? []).length;
  const formActions = Array.from(html.matchAll(/<form\b[^>]*action\s*=\s*["']([^"']*)["']/gi)).map((m) => m[1]);

  if (passwordFields > 0) {
    const foreignAction = formActions.find((action) => {
      if (!action || action.startsWith('#') || action.startsWith('javascript:')) return false;
      try {
        const target = new URL(action, pageUrl);
        return registrableDomain(target.hostname) !== pageRegistrable;
      } catch {
        return false;
      }
    });

    if (foreignAction) {
      findings.push({
        id: 'content.credential-exfil',
        severity: 'critical',
        title: 'Login form sends your password to another site',
        detail: `The password box on this page submits to ${safeHost(foreignAction) || foreignAction}, not to the site you are on. That is credential theft by design.`,
        weight: 55,
      });
    } else if (pageUrl.startsWith('http:')) {
      findings.push({
        id: 'content.password-no-tls',
        severity: 'critical',
        title: 'Password form with no encryption',
        detail: 'This page asks for a password over plain HTTP. Anything typed is readable on the network.',
        weight: 45,
      });
    } else {
      findings.push({
        id: 'content.password-form',
        severity: 'low',
        title: 'Password field present',
        detail: 'The page has a login box. Only continue if you navigated here yourself and the domain is right.',
        weight: 6,
      });
    }
  }

  // --- hidden iframes ----------------------------------------------------
  const iframeCount = (html.match(/<iframe\b/gi) ?? []).length;
  const hiddenIframe = /<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0|height\s*=\s*["']?0)/i.test(html);
  if (hiddenIframe) {
    findings.push({
      id: 'content.hidden-iframe',
      severity: 'high',
      title: 'Invisible embedded frame',
      detail: 'A hidden iframe is loaded on this page. It is used to pull in content or trigger actions you cannot see.',
      weight: 22,
    });
  }

  // --- obfuscated javascript --------------------------------------------
  const obfuscationHits = OBFUSCATION_PATTERNS.filter((pattern) => pattern.test(html)).length;
  const longBase64 = /[A-Za-z0-9+/]{600,}={0,2}/.test(html);
  if (obfuscationHits >= 2 || (obfuscationHits >= 1 && longBase64)) {
    findings.push({
      id: 'content.obfuscated-js',
      severity: 'high',
      title: 'Deliberately obfuscated JavaScript',
      detail: `Found ${obfuscationHits} obfuscation technique${obfuscationHits === 1 ? '' : 's'} (eval/atob/charCode tricks). Legitimate sites ship readable code.`,
      weight: 20,
    });
  } else if (obfuscationHits === 1) {
    findings.push({
      id: 'content.minor-obfuscation',
      severity: 'low',
      title: 'One obfuscation marker',
      detail: 'The page uses a JavaScript trick also common in packed or minified code. Not conclusive.',
      weight: 5,
    });
  }

  // --- crypto drainer ----------------------------------------------------
  const walletHits = countMatches(html, WALLET_ADDRESS_REGEX, 5);
  const drainerCopy = /(connect\s+wallet|validate\s+wallet|claim\s+airdrop|seed\s+phrase|recovery\s+phrase)/i.test(text);
  if (drainerCopy || walletHits >= 2) {
    findings.push({
      id: 'content.crypto-drainer',
      severity: 'critical',
      title: 'Crypto wallet drainer pattern',
      detail: 'The page asks you to connect or validate a wallet. This is the standard front end of a crypto drainer that empties the wallet.',
      weight: 45,
    });
  }

  // --- credential harvesting copy ---------------------------------------
  const theftMatches = CREDENTIAL_THEFT_PATTERNS.filter((pattern) => pattern.test(text));
  if (theftMatches.length > 0) {
    findings.push({
      id: 'content.credential-request',
      severity: 'critical',
      title: 'Page asks for OTP / PIN / seed phrase',
      detail: `Found: "${truncate(firstMatch(text, theftMatches) ?? 'OTP request', 90)}". No bank, company or government body ever asks for these.`,
      weight: 50,
    });
  }

  // --- urgency / pressure ------------------------------------------------
  const urgencyHits = URGENCY_PATTERNS.filter((pattern) => pattern.test(text)).length;
  if (urgencyHits >= 3) {
    findings.push({
      id: 'content.urgency-heavy',
      severity: 'high',
      title: 'Heavy panic wording',
      detail: `${urgencyHits} different "act now or lose your account" phrases on one page. Pressure is the core of every scam script.`,
      weight: 22,
    });
  } else if (urgencyHits === 2) {
    findings.push({
      id: 'content.urgency',
      severity: 'medium',
      title: 'Pressure / urgency wording',
      detail: `The page uses ${urgencyHits} urgency phrases (suspended, verify now, claim reward). Genuine notices rarely read like this.`,
      weight: 14,
    });
  } else if (urgencyHits === 1) {
    findings.push({
      id: 'content.urgency-mild',
      severity: 'low',
      title: 'One urgency phrase',
      detail: 'A single "act now" line appeared. Common in marketing too.',
      weight: 5,
    });
  }

  // --- cloaking / meta refresh ------------------------------------------
  const metaRefresh = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i);
  if (metaRefresh) {
    const target = metaRefresh[0].match(/url\s*=\s*['"]?([^'";>]+)/i)?.[1];
    const targetHost = target ? safeHost(target) : '';
    if (targetHost && registrableDomain(targetHost) !== pageRegistrable) {
      findings.push({
        id: 'content.meta-refresh-away',
        severity: 'high',
        title: 'Page instantly forwards you elsewhere',
        detail: `A meta refresh sends you to ${targetHost} right after loading. Used to dodge link scanners.`,
        weight: 24,
      });
    }
  }

  // --- JS-driven cross-domain redirect ----------------------------------
  const jsRedirect = html.match(/(?:window\.)?location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i);
  if (jsRedirect) {
    const targetHost = safeHost(jsRedirect[1]);
    if (targetHost && registrableDomain(targetHost) !== pageRegistrable) {
      findings.push({
        id: 'content.js-redirect-away',
        severity: 'medium',
        title: 'Script redirects to another domain',
        detail: `JavaScript sends visitors to ${targetHost}.`,
        weight: 16,
      });
    }
  }

  // --- external script sprawl -------------------------------------------
  const scriptHosts = new Set<string>();
  for (const match of html.matchAll(/<script\b[^>]*src\s*=\s*["'](?:https?:)?\/\/([^/"']+)/gi)) {
    scriptHosts.add(match[1].toLowerCase());
  }
  if (scriptHosts.size > 18) {
    findings.push({
      id: 'content.script-sprawl',
      severity: 'low',
      title: `${scriptHosts.size} external script sources`,
      detail: 'An unusually large number of third-party scripts for a single page.',
      weight: 6,
    });
  }

  // --- hidden text -------------------------------------------------------
  const hiddenText = /style\s*=\s*["'][^"']*(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"']*["']/i.test(html);
  const keywordStuffing = (lowerHtml.match(/(bank|login|verify|account|secure)/g) ?? []).length > 60;
  if (hiddenText && keywordStuffing) {
    findings.push({
      id: 'content.hidden-text',
      severity: 'medium',
      title: 'Hidden keyword text',
      detail: 'Content is hidden from visitors but visible to search engines and filters - a cloaking technique.',
      weight: 15,
    });
  }

  // --- parked / for-sale domain -----------------------------------------
  const parked = /(domain\s+(is\s+)?for\s+sale|buy\s+this\s+domain|this\s+domain\s+(is\s+)?parked|sedo|afternic)/i.test(text);
  if (parked) {
    findings.push({
      id: 'content.parked',
      severity: 'medium',
      title: 'Domain is parked or for sale',
      detail: 'Nobody is really running a service here. Content can change the moment someone buys it.',
      weight: 14,
    });
  }

  return {
    title,
    description,
    findings,
    textLength: text.length,
    passwordFields,
    formCount,
    iframeCount,
    externalScriptHosts: scriptHosts.size,
    parked,
  };
}

function extractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? decodeEntities(match[1]).replace(/\s+/g, ' ').trim() : '';
}

function extractMetaDescription(html: string): string {
  const match = html.match(/<meta[^>]+name\s*=\s*["']?description["']?[^>]*content\s*=\s*["']([^"']*)["']/i)
    ?? html.match(/<meta[^>]+content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']?description["']?/i);
  return match ? decodeEntities(match[1]).replace(/\s+/g, ' ').trim() : '';
}

function decodeEntities(value: string): string {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

function firstMatch(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[0];
  }
  return null;
}

function safeHost(value: string): string {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return '';
  }
}

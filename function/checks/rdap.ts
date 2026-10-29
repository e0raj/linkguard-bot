import type { Finding } from '../types';
import { fetchWithTimeout, isIpOrLocalHost } from '../utils';

export interface RdapResult {
  domainAgeDays: number | null;
  registrar: string | null;
  expiresInDays: number | null;
  findings: Finding[];
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown[];
  handle?: string;
}

interface RdapResponse {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  status?: string[];
}

const DAY_MS = 86_400_000;

/** Registration age via RDAP - free, no API key, works on Workers. */
export async function checkRdap(registrable: string): Promise<RdapResult> {
  if (!registrable || isIpOrLocalHost(registrable)) {
    return { domainAgeDays: null, registrar: null, expiresInDays: null, findings: [] };
  }

  let data: RdapResponse | null = null;
  for (const endpoint of [
    `https://rdap.org/domain/${encodeURIComponent(registrable)}`,
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(registrable)}`,
  ]) {
    try {
      const res = await fetchWithTimeout(endpoint, { headers: { accept: 'application/rdap+json' } }, 8000);
      if (!res.ok) continue;
      data = (await res.json()) as RdapResponse;
      break;
    } catch {
      // try the next endpoint
    }
  }

  if (!data) {
    return {
      domainAgeDays: null,
      registrar: null,
      expiresInDays: null,
      findings: [
        {
          id: 'rdap.unavailable',
          severity: 'info',
          title: 'Registration data unavailable',
          detail: 'The domain registry did not return whois data, so domain age could not be checked.',
          weight: 0,
        },
      ],
    };
  }

  const now = Date.now();
  const event = (action: string) => {
    const found = (data?.events ?? []).find((e) => (e.eventAction ?? '').toLowerCase() === action);
    if (!found?.eventDate) return null;
    const ts = Date.parse(found.eventDate);
    return Number.isNaN(ts) ? null : ts;
  };

  const created = event('registration');
  const expires = event('expiration');
  const domainAgeDays = created === null ? null : Math.floor((now - created) / DAY_MS);
  const expiresInDays = expires === null ? null : Math.floor((expires - now) / DAY_MS);

  let registrar: string | null = null;
  for (const entity of data.entities ?? []) {
    if (!entity.roles?.includes('registrar')) continue;
    const vcard = entity.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const field of vcard[1] as unknown[]) {
        if (Array.isArray(field) && field[0] === 'fn' && typeof field[3] === 'string') {
          registrar = field[3];
          break;
        }
      }
    }
    if (registrar) break;
  }

  const findings: Finding[] = [];

  if (domainAgeDays !== null) {
    if (domainAgeDays <= 7) {
      findings.push({
        id: 'rdap.newborn',
        severity: 'critical',
        title: 'Domain registered days ago',
        detail: `Registered ${domainAgeDays <= 0 ? 'today' : `${domainAgeDays} days ago`}. Almost every phishing site is used within its first week.`,
        weight: 35,
      });
    } else if (domainAgeDays <= 30) {
      findings.push({
        id: 'rdap.very-new',
        severity: 'high',
        title: 'Domain is less than a month old',
        detail: `Registered ${domainAgeDays} days ago. Real brands and shops have domains years old.`,
        weight: 25,
      });
    } else if (domainAgeDays <= 90) {
      findings.push({
        id: 'rdap.new',
        severity: 'medium',
        title: 'Domain is under 3 months old',
        detail: `Registered ${domainAgeDays} days ago. New domains carry more risk, though plenty are legitimate.`,
        weight: 12,
      });
    } else if (domainAgeDays >= 730) {
      findings.push({
        id: 'rdap.aged',
        severity: 'good',
        title: 'Long-standing domain',
        detail: `Registered over ${Math.floor(domainAgeDays / 365)} years ago and still running.`,
        weight: -12,
      });
    }
  }

  if (expiresInDays !== null && expiresInDays < 0) {
    findings.push({
      id: 'rdap.expired',
      severity: 'medium',
      title: 'Domain registration has expired',
      detail: 'The domain is past its expiry date. Content here can change hands at any time.',
      weight: 14,
    });
  }

  if (expiresInDays !== null && expiresInDays >= 0 && expiresInDays <= 30) {
    findings.push({
      id: 'rdap.expiring',
      severity: 'low',
      title: 'Domain expires soon',
      detail: `Registration ends in ${expiresInDays} days, so this site may not stay what it is.`,
      weight: 5,
    });
  }

  const suspended = (data.status ?? []).some((s) => /hold|suspended|pendingdelete|inactive/i.test(s));
  if (suspended) {
    findings.push({
      id: 'rdap.suspended',
      severity: 'high',
      title: 'Domain is suspended by the registry',
      detail: 'The registrar has put this domain on hold - usually for abuse or non-payment.',
      weight: 22,
    });
  }

  return { domainAgeDays, registrar, expiresInDays, findings };
}

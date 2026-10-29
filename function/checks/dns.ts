import type { Finding } from '../types';
import { fetchWithTimeout, isIpOrLocalHost } from '../utils';

export interface DnsResult {
  hasA: boolean;
  hasAAAA: boolean;
  hasMx: boolean;
  nameservers: string[];
  addresses: string[];
  findings: Finding[];
}

interface DohAnswer {
  Status: number;
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

async function doh(name: string, type: string, resolver = 'cloudflare-dns.com'): Promise<DohAnswer | null> {
  try {
    const res = await fetchWithTimeout(
      `https://${resolver}/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: 'application/dns-json' } },
      6000,
    );
    if (!res.ok) return null;
    return (await res.json()) as DohAnswer;
  } catch {
    return null;
  }
}

export async function checkDns(host: string): Promise<DnsResult> {
  const findings: Finding[] = [];

  if (isIpOrLocalHost(host)) {
    return {
      hasA: false,
      hasAAAA: false,
      hasMx: false,
      nameservers: [],
      addresses: [],
      findings: [
        {
          id: 'dns.skipped-local',
          severity: 'medium',
          title: 'Private or IP address',
          detail: 'This points at a raw address rather than a public website name.',
          weight: 10,
        },
      ],
    };
  }

  const [a, aaaa, mx, ns] = await Promise.all([
    doh(host, 'A'),
    doh(host, 'AAAA'),
    doh(host, 'MX'),
    doh(host, 'NS'),
  ]);

  const addresses = (a?.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
  const v6 = (aaaa?.Answer ?? []).filter((r) => r.type === 28).map((r) => r.data);
  const mxRecords = (mx?.Answer ?? []).filter((r) => r.type === 15).map((r) => r.data);
  const nameservers = (ns?.Answer ?? []).filter((r) => r.type === 2).map((r) => r.data.replace(/\.$/, ''));

  const hasA = addresses.length > 0 || v6.length > 0;
  const hasMx = mxRecords.length > 0;

  if (!hasA && a !== null) {
    findings.push({
      id: 'dns.no-a-record',
      severity: 'high',
      title: 'Domain does not resolve',
      detail: 'There is no website at this address. The link is dead or was taken down (often after abuse reports).',
      weight: 25,
    });
  }

  if (a === null && aaaa === null) {
    findings.push({
      id: 'dns.lookup-failed',
      severity: 'info',
      title: 'DNS lookup unavailable',
      detail: 'The resolver did not answer in time, so domain checks are partial.',
      weight: 0,
    });
  }

  if (hasA && !hasMx && mx !== null) {
    findings.push({
      id: 'dns.no-mx',
      severity: 'low',
      title: 'Domain cannot receive email',
      detail: 'No mail records exist, so any "your account" email that claims to come from here is fake.',
      weight: 6,
    });
  }

  const freeDns = nameservers.find((n) => /byet|freenom|dnspod|namecheaphosting|hostinger|000webhost/i.test(n));
  if (freeDns) {
    findings.push({
      id: 'dns.free-nameserver',
      severity: 'low',
      title: 'Free hosting nameservers',
      detail: `DNS is handled by ${freeDns}, a free hosting provider.`,
      weight: 7,
    });
  }

  return { hasA, hasAAAA: v6.length > 0, hasMx, nameservers, addresses, findings };
}

/**
 * Cloudflare's malware-blocking resolver (1.1.1.2) vs the plain one (1.1.1.1).
 * If the filtered resolver refuses a name that the plain one resolves,
 * Cloudflare's threat feed has already flagged it. Free, no key needed.
 */
export async function checkCloudflareFilter(host: string): Promise<'clean' | 'blocked' | 'skipped' | 'error'> {
  if (isIpOrLocalHost(host)) return 'skipped';
  try {
    const [plain, filtered] = await Promise.all([
      doh(host, 'A', 'cloudflare-dns.com'),
      doh(host, 'A', 'security.cloudflare-dns.com'),
    ]);
    if (!plain || !filtered) return 'error';
    const plainAnswers = (plain.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
    if (plainAnswers.length === 0) return 'skipped';
    const filteredAnswers = (filtered.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
    const blocked =
      filtered.Status !== 0 ||
      filteredAnswers.length === 0 ||
      filteredAnswers.every((ip) => ip === '0.0.0.0' || ip === '::');
    return blocked ? 'blocked' : 'clean';
  } catch {
    return 'error';
  }
}

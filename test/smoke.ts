/**
 * Live smoke test - hits the real internet through the full pipeline.
 * Run with:  npx esbuild test/smoke.ts --bundle --platform=node --format=esm --outfile=/tmp/smoke.mjs && node /tmp/smoke.mjs <url>
 */
import { analyzeLink } from '../function/analyze';
import { buildReport } from '../function/report';
import type { Env } from '../function/types';

const env: Env = {
  BOT_TOKEN: 'unused',
  MAX_SCANS_PER_DAY: '40',
  SCREENSHOT_FALLBACK: 'off',
};

const target = process.argv[2] ?? 'https://example.com';

const result = await analyzeLink(env, target);
console.log(buildReport(result).replace(/<[^>]+>/g, ''));
console.log('\n--- findings ---');
for (const finding of result.findings) {
  console.log(`${finding.severity.padEnd(8)} ${finding.id.padEnd(32)} ${finding.weight > 0 ? '+' : ''}${finding.weight}  ${finding.title}`);
}
console.log(`\nverdict=${result.verdict} score=${result.score} elapsed=${result.meta.elapsedMs}ms`);

#!/usr/bin/env node
/** Sanity-check a bot token without deploying anything. */
const token = process.env.BOT_TOKEN;
if (!token) {
  console.error('Usage: BOT_TOKEN=... node scripts/check-env.mjs');
  process.exit(1);
}
const res = await fetch(`https://api.telegram.org/bot${token}/getMe`);
const data = await res.json();
if (!data.ok) {
  console.error('Token rejected:', data.description);
  process.exit(1);
}
console.log(`Token OK -> @${data.result.username} (id ${data.result.id})`);

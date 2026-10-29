#!/usr/bin/env node
/** Remove the webhook so you can use long polling in local dev. */
const token = process.env.BOT_TOKEN;
if (!token) {
  console.error('Usage: BOT_TOKEN=... node scripts/delete-webhook.mjs');
  process.exit(1);
}
const res = await fetch(`https://api.telegram.org/bot${token}/deleteWebhook?drop_pending_updates=true`);
console.log(JSON.stringify(await res.json(), null, 2));

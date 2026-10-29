#!/usr/bin/env node
/**
 * Point Telegram at your deployed worker.
 *
 *   BOT_TOKEN=123:abc WORKER_URL=https://linkguard-bot.you.workers.dev \
 *   WEBHOOK_SECRET=some-long-random-string node scripts/set-webhook.mjs
 */
const token = process.env.BOT_TOKEN;
const workerUrl = process.env.WORKER_URL;
const secret = process.env.WEBHOOK_SECRET;

if (!token || !workerUrl) {
  console.error('Usage: BOT_TOKEN=... WORKER_URL=https://<worker-url> [WEBHOOK_SECRET=...] node scripts/set-webhook.mjs');
  process.exit(1);
}

const endpoint = `${workerUrl.replace(/\/$/, '')}/webhook`;
const body = {
  url: endpoint,
  allowed_updates: ['message', 'edited_message', 'callback_query'],
  drop_pending_updates: true,
};
if (secret) body.secret_token = secret;

const res = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});

const data = await res.json();
console.log(JSON.stringify(data, null, 2));
if (!data.ok) process.exit(1);
console.log(`\nWebhook set to ${endpoint}`);

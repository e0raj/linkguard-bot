import type { Env, ScanResult, TelegramCallbackQuery, TelegramMessage, TelegramUpdate } from './types';
import { analyzeLink } from './analyze';
import { buildProgressMessage, buildReport, buildScreenshotCaption } from './report';
import { checkRateLimit, recallLastUrl, rememberLastUrl } from './ratelimit';
import { escapeHtml, extractUrl, sha256Short, truncate } from './utils';

const API = 'https://api.telegram.org';

interface TgResult<T> {
  ok: boolean;
  result?: T;
  description?: string;
}

async function callTelegram<T>(env: Env, method: string, payload: Record<string, unknown>): Promise<TgResult<T>> {
  try {
    const res = await fetch(`${API}/bot${env.BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = (await res.json()) as TgResult<T>;
    if (!data.ok) console.error(`telegram ${method} failed: ${data.description ?? 'unknown'}`);
    return data;
  } catch (err) {
    console.error(`telegram ${method} threw: ${err instanceof Error ? err.message : String(err)}`);
    return { ok: false, description: 'network' };
  }
}

export function sendMessage(env: Env, chatId: number, text: string, extra: Record<string, unknown> = {}) {
  return callTelegram<TelegramMessage>(env, 'sendMessage', {
    chat_id: chatId,
    text,
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...extra,
  });
}

export function editMessage(env: Env, chatId: number, messageId: number, text: string, extra: Record<string, unknown> = {}) {
  return callTelegram<TelegramMessage>(env, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...extra,
  });
}

export function sendChatAction(env: Env, chatId: number, action = 'typing') {
  return callTelegram(env, 'sendChatAction', { chat_id: chatId, action });
}

export async function sendScreenshot(env: Env, chatId: number, result: ScanResult): Promise<void> {
  const shot = result.meta.screenshot;
  if (!shot || shot.bytes.byteLength === 0) return;

  const form = new FormData();
  form.append('chat_id', String(chatId));
  form.append('caption', buildScreenshotCaption(result));
  form.append('parse_mode', 'HTML');
  form.append('photo', new Blob([shot.bytes], { type: shot.contentType || 'image/jpeg' }), 'screenshot.jpg');

  try {
    const res = await fetch(`${API}/bot${env.BOT_TOKEN}/sendPhoto`, { method: 'POST', body: form });
    if (!res.ok) {
      const text = await res.text();
      console.error(`sendPhoto failed: ${text.slice(0, 200)}`);
    }
  } catch (err) {
    console.error(`sendPhoto threw: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function answerCallback(env: Env, callbackId: string, text?: string) {
  return callTelegram(env, 'answerCallbackQuery', { callback_query_id: callbackId, text });
}

const WELCOME = [
  '<b>LinkGuard</b> — send me any link and I will tell you if it is safe.',
  '',
  'What I actually do, on my own server, before answering:',
  '• open the link in a real browser and screenshot it',
  '• follow every redirect and check the final domain',
  '• check DNS, mail records and whois registration age',
  '• read the page source for fake login forms, hidden iframes, obfuscated scripts and OTP requests',
  '• cross-check Google Safe Browsing, URLhaus and the Cloudflare malware feed',
  '• look for lookalike domains and brand impersonation',
  '',
  'Just paste a link — no command needed.',
  '',
  'Commands: /start /help /about /privacy',
].join('\n');

const HELP = [
  '<b>How to use LinkGuard</b>',
  '',
  'Paste any of these and I will scan it:',
  '• <code>https://example.com/login</code>',
  '• <code>example.com</code>',
  '• a shortened link like <code>bit.ly/xyz</code> (I follow it to the real page)',
  '',
  '<b>Reading the result</b>',
  '✅ <b>SAFE</b> — nothing suspicious found, still check the domain before logging in.',
  '⚠️ <b>SUSPICIOUS</b> — some signals are off. Do not enter passwords or OTPs.',
  '⛔ <b>DANGEROUS</b> — treat it as hostile. Delete it and warn whoever sent it.',
  '',
  'Risk score is 0–100. Anything above 55 is dangerous. One critical finding (fake login form, OTP request, known threat feed hit) always pushes the verdict to dangerous, no matter how clean everything else looks.',
  '',
  'Commands: /help /about /privacy',
].join('\n');

const ABOUT = [
  '<b>About LinkGuard</b>',
  '',
  'A Telegram front end for a link-safety scanner running on Cloudflare Workers.',
  '',
  'Every scan is a real visit: the worker fetches the page, reads the HTML, checks DNS and RDAP registration data, and renders a screenshot in headless Chromium. No JavaScript from the scanned page is ever executed on my side, and nothing is stored about you beyond a daily scan counter.',
  '',
  'Built because forwarded links are how most scams reach Indian families — and nobody has time to check them by hand.',
].join('\n');

const PRIVACY = [
  '<b>Privacy</b>',
  '',
  '• I do not store the links you send. A daily counter per user ID is kept only to enforce the rate limit.',
  '• Scan results are cached for a few hours by URL, never by user.',
  '• The scanned site sees a request from Cloudflare, the same as any visitor.',
  '• If a screenshot needs a third-party renderer, the URL is sent to that renderer.',
  '• Optional reputation lookups (Google Safe Browsing, VirusTotal, URLhaus) receive only the URL being scanned.',
  '',
  'LinkGuard gives automated advice. It cannot see a page that shows different content to different visitors, so a "safe" verdict is not a guarantee.',
].join('\n');

export async function handleUpdate(env: Env, update: TelegramUpdate): Promise<void> {
  try {
    if (update.callback_query) {
      await handleCallback(env, update.callback_query);
      return;
    }
    const message = update.message ?? update.edited_message;
    if (!message?.text) return;
    await handleMessage(env, message);
  } catch (err) {
    console.error(`handleUpdate failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  }
}

async function handleMessage(env: Env, message: TelegramMessage): Promise<void> {
  const chatId = message.chat.id;
  const text = message.text?.trim() ?? '';
  if (!text) return;

  const command = text.split(/\s+/)[0].toLowerCase().split('@')[0];

  if (command === '/start') {
    await sendMessage(env, chatId, WELCOME);
    return;
  }
  if (command === '/help') {
    await sendMessage(env, chatId, HELP);
    return;
  }
  if (command === '/about') {
    await sendMessage(env, chatId, ABOUT);
    return;
  }
  if (command === '/privacy') {
    await sendMessage(env, chatId, PRIVACY);
    return;
  }
  if (command === '/rescan' || command === '/again') {
    const last = await recallLastUrl(env, chatId);
    if (!last) {
      await sendMessage(env, chatId, 'Nothing to re-scan yet. Send me a link first.');
      return;
    }
    await runScan(env, chatId, message.from?.id ?? 0, last, null);
    return;
  }

  const url = extractUrl(text);
  if (!url) {
    await sendMessage(
      env,
      chatId,
      'I could not find a link in that message.\n\nSend something like <code>example.com</code> or <code>https://example.com/login</code>, or type /help.',
    );
    return;
  }

  await runScan(env, chatId, message.from?.id ?? 0, url, null);
}

async function runScan(
  env: Env,
  chatId: number,
  userId: number,
  url: string,
  existingMessageId: number | null,
): Promise<void> {
  const rate = await checkRateLimit(env, userId);
  if (!rate.allowed) {
    const text = `Daily limit reached (${rate.limit} scans). It resets at midnight UTC.`;
    if (existingMessageId) await editMessage(env, chatId, existingMessageId, text);
    else await sendMessage(env, chatId, text);
    return;
  }

  let progressId = existingMessageId;
  const progressText = buildProgressMessage(url, 'Opening the page in a real browser…');

  if (progressId) {
    await editMessage(env, chatId, progressId, progressText);
  } else {
    const sent = await sendMessage(env, chatId, progressText);
    progressId = sent.result?.message_id ?? null;
  }
  await sendChatAction(env, chatId, 'typing');

  let result: ScanResult;
  try {
    result = await analyzeLink(env, url);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    console.error(`scan failed for ${url}: ${detail}`);
    const failure = `Scan failed for <code>${escapeHtml(truncate(url, 80))}</code>.\n\nThe site may be blocking automated visitors. Try again in a moment.`;
    if (progressId) await editMessage(env, chatId, progressId, failure);
    else await sendMessage(env, chatId, failure);
    return;
  }

  const report = buildReport(result);
  const keyboard = env.CACHE
    ? {
        inline_keyboard: [
          [
            { text: '🔄 Re-scan', callback_data: 'rescan' },
            { text: '📋 Details', callback_data: 'details' },
          ],
          [{ text: '❓ How to read this', callback_data: 'help' }],
        ],
      }
    : undefined;

  if (progressId) {
    const edited = await editMessage(env, chatId, progressId, report, keyboard ? { reply_markup: keyboard } : {});
    if (!edited.ok) await sendMessage(env, chatId, report, keyboard ? { reply_markup: keyboard } : {});
  } else {
    await sendMessage(env, chatId, report, keyboard ? { reply_markup: keyboard } : {});
  }

  await sendScreenshot(env, chatId, result);
  await rememberLastUrl(env, chatId, result.meta.finalUrl || url);

  // Keep a small cache entry so repeated links are instant.
  if (env.CACHE) {
    const key = `scan:${await sha256Short(result.meta.finalUrl || url)}`;
    await env.CACHE.put(key, JSON.stringify({ verdict: result.verdict, score: result.score, at: result.meta.checkedAt }), {
      expirationTtl: 6 * 60 * 60,
    });
  }
}

async function handleCallback(env: Env, query: TelegramCallbackQuery): Promise<void> {
  const chatId = query.message?.chat.id;
  const data = query.data ?? '';
  await answerCallback(env, query.id);

  if (!chatId) return;

  if (data === 'help') {
    await sendMessage(env, chatId, HELP);
    return;
  }

  const last = await recallLastUrl(env, chatId);
  if (!last) {
    await sendMessage(env, chatId, 'Send me a link first, then I can re-scan it.');
    return;
  }

  if (data === 'rescan') {
    await runScan(env, chatId, query.from.id, last, null);
    return;
  }

  if (data === 'details') {
    await sendMessage(
      env,
      chatId,
      [
        '<b>What each check means</b>',
        '',
        '🔴 <b>Domain age</b> — whois registration date. Phishing sites are usually days old.',
        '🔴 <b>Threat feeds</b> — Google Safe Browsing, URLhaus, Cloudflare malware resolver.',
        '🔴 <b>Fake login form</b> — a password box that posts to a different domain.',
        '🔴 <b>OTP / PIN request</b> — never legitimate, from anyone.',
        '🟠 <b>Lookalike domain</b> — non-Latin characters that resemble a real brand.',
        '🟠 <b>Redirect chain</b> — how many hops before the real page.',
        '🟠 <b>Obfuscated script</b> — eval/atob packing, used to hide payloads.',
        '',
        'Re-scan: /rescan',
      ].join('\n'),
    );
  }
}

# LinkGuard — a Telegram bot that actually opens the link

Send it any link. It opens the page in a real browser, follows every redirect,
reads the HTML, checks DNS and whois, cross-references threat feeds, takes a
screenshot, and only then tells you whether the link is safe.

Built for the way scams actually spread in India: forwarded messages. A
relative forwards "your electricity will be disconnected, pay here", and nobody
has a way to check it in ten seconds. Now they do.

```
you:  https://paytm.secure-verify.tk/login

bot:  ⛔ DANGEROUS · risk score 100/100
      Do not open this link, and never type anything into it.

      Domain       secure-verify.tk
      Domain age   2 days · NameSilo
      Transport    HTTPS ✅ · HTTP 200
      Redirects    2 · 18 KB page
      Threat feeds Safe Browsing: clean · CF filter: THREAT

      ⛔ Pretends to be Paytm — "paytm.secure-verify.tk" mentions Paytm
         but is registered to secure-verify.tk, which Paytm does not own.
      ⛔ Domain registered days ago — Registered 2 days ago. Almost every
         phishing site is used within its first week.
      ⛔ Login form sends your password to another site — the password box
         submits to collect.evil.tk, not to the site you are on.
      [screenshot attached]
```

## What it checks

**The URL string** — HTTPS, raw IP hosts, `user@host` tricks, punycode and
Cyrillic homoglyphs (`аpple.com`), invisible Unicode, high-abuse TLDs, subdomain
stacking, odd ports, free hosting, brand impersonation, direct `.apk`/`.exe`
downloads, percent-encoded path tricks, URL shorteners.

**The domain** — A/AAAA/MX/NS records over DNS-over-HTTPS, registration date and
registrar over RDAP (no API key needed), expiry, registry suspension status.

**The page** — every redirect hop, final domain, status code, TLS, security
headers, then the HTML itself: password forms and where they POST to, hidden
iframes, `eval`/`atob` obfuscation, crypto-drainer patterns, OTP/PIN/seed-phrase
requests, urgency copy, meta-refresh and JS redirects to other domains, hidden
keyword text, parked domains.

**Reputation feeds** — Google Safe Browsing (key optional), VirusTotal (key
optional), abuse.ch URLhaus (free), and a clever free one: Cloudflare's
malware-blocking resolver `1.1.1.2` versus plain `1.1.1.1`. If the filtered
resolver refuses a name the plain one resolves, Cloudflare's threat feed has
already flagged it.

**Visual evidence** — a screenshot from headless Chromium via Cloudflare Browser
Rendering, sent to the chat with the verdict.

## Scoring

Findings carry weights, trust signals carry negative weights, the total is
clamped to 0–100.

| Score | Verdict |
|-------|---------|
| 0–20 | ✅ SAFE |
| 21–55 | ⚠️ SUSPICIOUS |
| 56–100 | ⛔ DANGEROUS |

A single **critical** finding (fake login form, OTP request, known threat-feed
hit, newborn domain with brand impersonation) floors the score at 60 no matter
how clean everything else looks. Clean signals can never average away one real
red flag — that is the whole point of a safety tool.

## Deploy (Cloudflare Workers)

```bash
git clone https://github.com/e0raj/linkguard-bot.git
cd linkguard-bot
npm install

# 1. Bot token from @BotFather
npx wrangler secret put BOT_TOKEN

# 2. A random shared secret so only Telegram can call your webhook
npx wrangler secret put WEBHOOK_SECRET

# 3. Optional reputation feeds
npx wrangler secret put SAFE_BROWSING_KEY     # https://developers.google.com/safe-browsing
npx wrangler secret put VIRUSTOTAL_KEY        # https://www.virustotal.com/gui/my-apikey

# 4. Optional but recommended: caching + rate limiting
npx wrangler kv namespace create CACHE
#    paste the printed id into wrangler.toml and uncomment the block

# 5. Ship it
npx wrangler deploy

# 6. Point Telegram at the worker
BOT_TOKEN=123:abc WORKER_URL=https://linkguard-bot.<you>.workers.dev \
WEBHOOK_SECRET=<same-secret> npm run set-webhook
```

Open your bot, send `/start`, paste a link.

### Notes on the paid features

- **Browser Rendering** (`[browser]` in `wrangler.toml`) needs the Workers Paid
  plan. Remove the block and the bot falls back to free third-party renderers
  (WordPress mShots, thum.io). Set `SCREENSHOT_FALLBACK = "off"` to disable
  third-party rendering entirely — useful if you would rather not send URLs
  to a third party.
- **KV** is optional. Without it the bot still works, but there is no caching,
  no per-user daily quota, and no inline buttons.

### Local development

```bash
cp .dev.vars.example .dev.vars   # fill in BOT_TOKEN
npx wrangler dev                 # worker on http://localhost:8787
# then, in another shell, tunnel it and set the webhook, or call /scan directly
curl -H "Authorization: Bearer $ADMIN_KEY" "http://localhost:8787/scan?url=https://example.com"
```

## HTTP API

Set `ADMIN_KEY` to unlock a plain JSON endpoint, handy for a website widget or
for testing without Telegram:

```bash
curl -H "Authorization: Bearer $ADMIN_KEY" \
  "https://linkguard-bot.you.workers.dev/scan?url=https://example.com"
```

Returns the full scan result: verdict, score, every finding with severity and
weight, plus domain metadata and the rendered report.

## Tests

```bash
npm run typecheck   # tsc --noEmit, strict
npm test            # 32 offline tests: URL parsing, HTML heuristics, scoring, report
```

The test suite needs no network and no Telegram token — it exercises the pure
logic. `test/smoke.ts` runs the full live pipeline against one URL.

## Layout

```
function/                 all backend code
  index.ts                worker entry: /webhook, /health, /scan
  telegram.ts             Bot API client, commands, message flow
  analyze.ts              the scan orchestrator
  scoring.ts              findings -> risk score -> verdict
  report.ts               Telegram HTML report
  ratelimit.ts            daily quota + caching (KV, optional)
  utils.ts                URL extraction, punycode, capped fetch, escaping
  constants.ts            TLD lists, brands, regex patterns
  types.ts                shared types
  checks/
    url.ts                URL string heuristics
    dns.ts                DoH lookups + Cloudflare malware resolver comparison
    rdap.ts               whois/registration age over RDAP
    http.ts               fetch, redirect chain, headers, capped body
    content.ts            HTML: forms, scripts, cloaking, social engineering
    reputation.ts         Safe Browsing, VirusTotal, URLhaus
    screenshot.ts         Browser Rendering + free fallback
scripts/                  set-webhook, delete-webhook, check-env
test/                     offline tests + live smoke test
```

## Limits — read this before trusting a green tick

- A **SAFE** verdict means nothing suspicious was found, not that the site is
  good. Pages can serve different content to a scanner than to you (cloaking),
  and a legitimate site can be compromised tomorrow.
- Sites behind a login, a CAPTCHA, or aggressive bot protection give a partial
  scan. The report says so when it happens.
- The bot refuses localhost, private IPs and bare IP hosts on purpose — it is
  not a network scanner.
- Scans are cached by URL, never by user. Nothing about you is stored beyond a
  daily counter keyed on your Telegram user id.
- This is automated advice. For anything involving money, verify on the official
  app or website you already use.

## License

MIT

/** Shared types for LinkGuard. */

export interface Env {
  /** Telegram bot token from @BotFather. */
  BOT_TOKEN: string;
  /** Optional shared secret for the webhook (recommended). */
  WEBHOOK_SECRET?: string;
  /** Cloudflare Browser Rendering binding. */
  BROWSER?: Fetcher;
  /** Optional KV namespace for caching + rate limiting. */
  CACHE?: KVNamespace;
  /** Optional Google Safe Browsing v4 API key. */
  SAFE_BROWSING_KEY?: string;
  /** Optional VirusTotal v3 API key. */
  VIRUSTOTAL_KEY?: string;
  /** Optional key that unlocks the /scan HTTP API. */
  ADMIN_KEY?: string;
  /** Scans allowed per user per day (string from vars). */
  MAX_SCANS_PER_DAY?: string;
  /** "on" | "off" - allow third party screenshot fallback. */
  SCREENSHOT_FALLBACK?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'good';

export interface Finding {
  /** Stable id, used for de-duplication and for the "why" list. */
  id: string;
  severity: Severity;
  /** Short human label, shown to the user. */
  title: string;
  /** One line of evidence. */
  detail: string;
  /** Contribution to the risk score. Negative values are trust credits. */
  weight: number;
}

export type VerdictLevel = 'safe' | 'caution' | 'danger' | 'unknown';

export interface ScanMeta {
  inputUrl: string;
  finalUrl: string;
  host: string;
  unicodeHost: string;
  registrableDomain: string;
  scheme: string;
  statusCode: number;
  redirectCount: number;
  contentType: string;
  title: string;
  description: string;
  domainAgeDays: number | null;
  registrar: string | null;
  expiresInDays: number | null;
  hasA: boolean;
  hasMx: boolean;
  nameservers: string[];
  hsts: boolean;
  csp: boolean;
  serverHeader: string;
  pageBytes: number;
  screenshot: ScreenshotResult | null;
  reputation: ReputationResult;
  elapsedMs: number;
  checkedAt: string;
}

export interface ScreenshotResult {
  bytes: Uint8Array;
  contentType: string;
  source: 'browser-rendering' | 'fallback' | 'none';
  note?: string;
}

export interface ReputationResult {
  safeBrowsing: 'clean' | 'threat' | 'skipped' | 'error';
  safeBrowsingThreats: string[];
  virusTotal: 'clean' | 'threat' | 'unknown' | 'skipped' | 'error';
  virusTotalPositives: number;
  virusTotalEngines: number;
  urlhaus: 'clean' | 'threat' | 'skipped' | 'error';
  cloudflareFilter: 'clean' | 'blocked' | 'skipped' | 'error';
}

export interface ScanResult {
  verdict: VerdictLevel;
  score: number;
  findings: Finding[];
  meta: ScanMeta;
  /** Human readable one-liner. */
  headline: string;
}

export interface TelegramUser {
  id: number;
  is_bot?: boolean;
  first_name?: string;
  username?: string;
}

export interface TelegramMessage {
  message_id: number;
  from?: TelegramUser;
  chat: { id: number; type: string; title?: string };
  text?: string;
  date: number;
  reply_to_message?: TelegramMessage;
}

export interface TelegramCallbackQuery {
  id: string;
  from: TelegramUser;
  data?: string;
  message?: TelegramMessage;
}

export interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  edited_message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
}

/** Static knowledge used by the heuristics. Keep it boring and auditable. */

/** TLDs that are heavily abused by phishing kits. */
export const HIGH_RISK_TLDS: string[] = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'buzz', 'click', 'work', 'loan', 'win',
  'bid', 'download', 'stream', 'gdn', 'icu', 'cyou', 'monster', 'quest', 'rest',
  'cam', 'sbs', 'lol', 'cfd', 'zip', 'mov', 'autos', 'bond', 'beauty', 'hair',
  'skin', 'makeup', 'mom', 'boats', 'christmas', 'country', 'kim', 'cricket',
  'science', 'party', 'review', 'trade', 'webcam', 'men', 'date', 'faith',
];

/** TLDs that are cheap-but-common. Worth a nudge, not an alarm. */
export const MEDIUM_RISK_TLDS: string[] = [
  'xyz', 'link', 'shop', 'online', 'site', 'store', 'space', 'website', 'live',
  'fun', 'pro', 'pw', 'cc', 'su', 'ws', 'biz', 'info', 'one', 'help',
];

/** TLDs that are strongly associated with real institutions. */
export const TRUSTED_TLDS: string[] = [
  'gov.in', 'nic.in', 'ac.in', 'edu.in', 'res.in', 'gov', 'mil', 'edu', 'int',
];

export const URL_SHORTENERS: string[] = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy',
  'shorturl.at', 'rebrand.ly', 'ow.ly', 'buff.ly', 'tiny.cc', 'lnkd.in', 's.id',
  'clck.ru', 'v.gd', 't.ly', 'short.io', 'bl.ink', 'shrtco.de', '1url.com',
  'bit.do', 'x.co', 'u.to', 'cli.gs', 'adf.ly', 'sh.st', 'soo.gd', 'trib.al',
  'linkvertise.com', 'ouo.io', 'boost.ink', 'surl.li', 'cutt.us', 'chilp.it',
  'tiny.one', 'shorte.st', 'bc.vc', 'ity.im', 'qps.ru', 'mzl.la',
];

/** Free / shared hosting where a "bank" suddenly appearing is odd. */
export const FREE_HOSTING_SUFFIXES: string[] = [
  '000webhostapp.com', 'weebly.com', 'wixsite.com', 'blogspot.com',
  'godaddysites.com', 'netlify.app', 'vercel.app', 'github.io', 'web.app',
  'firebaseapp.com', 'glitch.me', 'repl.co', 'surge.sh', 'pages.dev',
  'workers.dev', 'r2.dev', 'herokuapp.com', 'onrender.com', 'epizy.com',
  'byethost.com', 'infinityfreeapp.com', 'freehostia.com', '000webhost.com',
  'altervista.org', 'my.id', 'webnode.page', 'strikingly.com', 'carrd.co',
  'notion.site', 'gitbook.io', 'duckdns.org', 'ngrok.io', 'ngrok-free.app',
];

/** Brands that get impersonated constantly. Short ones need exact labels. */
export const PROTECTED_BRANDS: string[] = [
  // India - payments / banking
  'paytm', 'phonepe', 'gpay', 'googlepay', 'bhim', 'upi', 'npci', 'razorpay',
  'paypal', 'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'yesbank', 'idfc',
  'bankofbaroda', 'pnb', 'canara', 'unionbank', 'rbi', 'irctc', 'aadhaar',
  'uidai', 'epfo', 'incometax', 'gst', 'digilocker', 'umang', 'cowin',
  // India - services / commerce
  'amazon', 'flipkart', 'myntra', 'swiggy', 'zomato', 'ola', 'uber', 'jio',
  'airtel', 'vi', 'bsnl', 'tata', 'reliance', 'dmart', 'bigbasket', 'nykaa',
  'meesho', 'snapdeal', 'makemytrip', 'irctc', 'indigo', 'vistara', 'spicejet',
  // Global
  'google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp',
  'telegram', 'twitter', 'linkedin', 'microsoft', 'outlook', 'office365',
  'apple', 'icloud', 'netflix', 'spotify', 'steam', 'binance', 'coinbase',
  'metamask', 'trustwallet', 'kraken', 'wazirx', 'coindcx', 'dropbox',
  'adobe', 'dhl', 'fedex', 'usps', 'irs', 'hmrc', 'visa', 'mastercard',
];

/** Words that look official but live on attacker infrastructure. */
export const PHISHY_HOST_WORDS: string[] = [
  'login', 'signin', 'verify', 'verification', 'secure', 'security', 'account',
  'update', 'confirm', 'billing', 'wallet', 'kyc', 'support', 'recovery',
  'unlock', 'auth', 'reset', 'password', 'alert', 'notice', 'refund',
  'cashback', 'reward', 'claim', 'winner', 'lucky', 'gift', 'offer',
];

/** Urgency / pressure copy found in almost every phishing page. */
export const URGENCY_PATTERNS: RegExp[] = [
  /account\s+(has\s+been\s+|will\s+be\s+)?(suspended|blocked|locked|deactivated|closed)/i,
  /within\s+(24|48|12|2)\s*(hours|hrs)/i,
  /(verify|confirm|update)\s+(your\s+)?(account|details|information|kyc)\s+(now|immediately|today)/i,
  /(click|tap)\s+(here\s+)?(to\s+)?(verify|confirm|unlock|reactivate)/i,
  /you\s+(have\s+)?won\s+(a\s+)?(prize|lottery|reward|iphone|cash|₹|rs)/i,
  /congratulations[,\s]+you/i,
  /claim\s+(your\s+)?(reward|prize|cashback|gift)/i,
  /last\s+(chance|warning)\s+to/i,
  /(immediate|urgent)\s+action\s+required/i,
  /your\s+(sim|number)\s+will\s+be\s+(blocked|deactivated)/i,
  /electricity\s+(bill|connection)\s+will\s+be\s+(disconnected|cut)/i,
  /(pay|settle)\s+(the\s+)?(pending|outstanding)\s+(amount|dues)/i,
  /free\s+(gift|recharge|data)\s+(worth|of)/i,
];

/** Never legitimate. A real page will never ask for these in body text. */
export const CREDENTIAL_THEFT_PATTERNS: RegExp[] = [
  /\b(share|send|enter|provide)\s+(your\s+)?(otp|one[\s-]?time\s+password|pin|cvv|atm\s*pin)\b/i,
  /\botp\s+(bhejo|bhej\s+do|share\s+karo|batado|bata\s+do)\b/i,
  /\b(seed\s+phrase|recovery\s+phrase|mnemonic|private\s+key)\b/i,
  /\b(connect\s+wallet|validate\s+wallet|sync\s+wallet|airdrop\s+claim)\b/i,
  /\b(12|24)[\s-]word\s+(phrase|seed)\b/i,
];

/** Obfuscation / evasion markers inside inline JS. */
export const OBFUSCATION_PATTERNS: RegExp[] = [
  /\beval\s*\(/i,
  /\batob\s*\(/i,
  /\bunescape\s*\(/i,
  /\bfromCharCode\s*\(/i,
  /document\.write\s*\(\s*unescape/i,
  /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,
  /\bdecodeURIComponent\s*\(\s*escape\s*\(/i,
];

/** Executables nobody should be downloading from a random link. */
export const DANGEROUS_EXTENSIONS: string[] = [
  '.apk', '.exe', '.scr', '.msi', '.bat', '.cmd', '.vbs', '.jar', '.dmg',
  '.pkg', '.hta', '.ps1', '.iso', '.img', '.crx', '.xlsm', '.docm',
];

export const WALLET_ADDRESS_REGEX = /\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/;

/** Two-label public suffixes we care about for registrable-domain math. */
export const MULTI_LABEL_SUFFIXES: string[] = [
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in',
  'nic.in', 'ac.in', 'edu.in', 'res.in', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'com.br', 'com.mx',
  'com.sg', 'com.my', 'co.jp', 'or.jp', 'com.cn', 'com.tr', 'com.sa',
  'co.ae', 'com.pk', 'com.bd', 'com.np', 'co.il', 'com.hk', 'com.tw',
];

/** Score at or below this = safe. */
export const SAFE_THRESHOLD = 20;
/** Score above this = dangerous. */
export const DANGER_THRESHOLD = 55;

export const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

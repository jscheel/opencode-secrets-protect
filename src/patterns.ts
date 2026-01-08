export interface SecretPattern {
  name: string;
  pattern: RegExp;
  minLength: number;
  allowsSpaces: boolean;
  /** If true, skip safe pattern check for this pattern (high confidence patterns) */
  highConfidence?: boolean;
}

const AWS_ACCESS_KEY_ID = /AKIA[0-9A-Z]{16}/;
const AWS_SECRET_ACCESS_KEY = /(?:aws)?_?(?:secret)?_?(?:access)?_?key['"\s:=]+['"]?[0-9a-zA-Z/+]{40}['"]?/i;

const GITHUB_OAUTH = /gho_[0-9a-zA-Z]{36}/;
const GITHUB_APP_TOKEN = /(?:ghu|ghs)_[0-9a-zA-Z]{36}/;
const GITHUB_TOKEN = /ghp_[0-9a-zA-Z]{36}/;
const GITHUB_FINE_GRAINED_TOKEN = /github_pat_[0-9a-zA-Z_]{22,}/;

const GITLAB_TOKEN = /glpat-[0-9a-zA-Z\-_]{20,}/;
const GITLAB_RUNNER_TOKEN = /glrt-[0-9a-zA-Z_\-]{20,}/;

const SLACK_TOKEN = /xox[baprs]-[0-9a-zA-Z\-]{10,48}/;
const SLACK_WEBHOOK = /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/;

const JWT = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/;

const GOOGLE_API_KEY = /AIza[0-9A-Za-z\-_]{35}/;
const GOOGLE_OAUTH = /ya29\.[0-9A-Za-z\-_]+/;
const GOOGLE_SERVICE_ACCOUNT = /"type"\s*:\s*["']service_account["']/;

const STRIPE_SECRET_KEY = /sk_live_[0-9a-zA-Z]{24,}/;
const STRIPE_RESTRICTED_KEY = /rk_live_[0-9a-zA-Z]{24,}/;

const TWILIO_API_KEY = /SK[a-z0-9]{32}/;

const SENDGRID_API_KEY = /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{40,}/;

const DISCORD_BOT_TOKEN = /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/;
const DISCORD_WEBHOOK = /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+/;

const OPENAI_API_KEY = /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/;
const OPENAI_API_KEY_NEW = /sk-(?:proj-)?[a-zA-Z0-9\-_]{40,}/;

const ANTHROPIC_API_KEY = /sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{80,}/;

const NPM_TOKEN = /npm_[a-zA-Z0-9]{36}/;

const PYPI_TOKEN = /pypi-[a-zA-Z0-9_\-]{50,}/;

const HEROKU_API_KEY = /[hH]eroku[a-zA-Z0-9\-_]*['"\s:=]+['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?/;

const PASSWORD_IN_URL = /[a-zA-Z]{3,10}:\/\/[^/\s:@]{3,20}:[^/\s:@]{3,20}@[^\s'"]+/;

const RSA_PRIVATE_KEY = /-----BEGIN RSA PRIVATE KEY-----/;
const OPENSSH_PRIVATE_KEY = /-----BEGIN OPENSSH PRIVATE KEY-----/;
const DSA_PRIVATE_KEY = /-----BEGIN DSA PRIVATE KEY-----/;
const EC_PRIVATE_KEY = /-----BEGIN EC PRIVATE KEY-----/;
const PGP_PRIVATE_KEY = /-----BEGIN PGP PRIVATE KEY BLOCK-----/;
const GENERIC_PRIVATE_KEY = /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/;

const MONGODB_URI = /mongodb(?:\+srv)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/;
const POSTGRES_URI = /postgres(?:ql)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/;
const MYSQL_URI = /mysql:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/;
const REDIS_URI = /redis:\/\/[^\s'"]*:[^\s'"]+@[^\s'"]+/;

const BEARER_TOKEN = /[Bb]earer\s+[a-zA-Z0-9\-._~+/]+=*/;
const BASIC_AUTH = /[Bb]asic\s+[a-zA-Z0-9+/]{20,}={0,2}/;
const API_KEY_ASSIGNMENT = /(?:api[_-]?key|apikey|api[_-]?secret)['"\s:=]+['"]?[a-zA-Z0-9\-._]{20,}['"]?/i;
const SECRET_ASSIGNMENT = /(?:secret|token|password|passwd|pwd)['"\s:=]+['"]?[a-zA-Z0-9\-._!@#$%^&*]{8,}['"]?/i;

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key ID", pattern: AWS_ACCESS_KEY_ID, minLength: 16, allowsSpaces: false, highConfidence: true },
  { name: "AWS Secret Access Key", pattern: AWS_SECRET_ACCESS_KEY, minLength: 30, allowsSpaces: false, highConfidence: true },

  { name: "GitHub OAuth Token", pattern: GITHUB_OAUTH, minLength: 36, allowsSpaces: false, highConfidence: true },
  { name: "GitHub App Token", pattern: GITHUB_APP_TOKEN, minLength: 36, allowsSpaces: false, highConfidence: true },
  { name: "GitHub Personal Access Token", pattern: GITHUB_TOKEN, minLength: 36, allowsSpaces: false, highConfidence: true },
  { name: "GitHub Fine-Grained Token", pattern: GITHUB_FINE_GRAINED_TOKEN, minLength: 26, allowsSpaces: false, highConfidence: true },

  { name: "GitLab Personal Access Token", pattern: GITLAB_TOKEN, minLength: 20, allowsSpaces: false, highConfidence: true },
  { name: "GitLab Runner Token", pattern: GITLAB_RUNNER_TOKEN, minLength: 20, allowsSpaces: false, highConfidence: true },

  { name: "Slack Token", pattern: SLACK_TOKEN, minLength: 15, allowsSpaces: false, highConfidence: true },
  { name: "Slack Webhook URL", pattern: SLACK_WEBHOOK, minLength: 60, allowsSpaces: false, highConfidence: true },

  { name: "JSON Web Token (JWT)", pattern: JWT, minLength: 36, allowsSpaces: false, highConfidence: true },

  { name: "Google API Key", pattern: GOOGLE_API_KEY, minLength: 35, allowsSpaces: false, highConfidence: true },
  { name: "Google OAuth Token", pattern: GOOGLE_OAUTH, minLength: 10, allowsSpaces: false, highConfidence: true },
  { name: "Google Service Account", pattern: GOOGLE_SERVICE_ACCOUNT, minLength: 15, allowsSpaces: true, highConfidence: true },

  { name: "Stripe Secret Key", pattern: STRIPE_SECRET_KEY, minLength: 24, allowsSpaces: false, highConfidence: true },
  { name: "Stripe Restricted Key", pattern: STRIPE_RESTRICTED_KEY, minLength: 24, allowsSpaces: false, highConfidence: true },

  { name: "Twilio API Key", pattern: TWILIO_API_KEY, minLength: 30, allowsSpaces: false, highConfidence: true },

  { name: "SendGrid API Key", pattern: SENDGRID_API_KEY, minLength: 40, allowsSpaces: false, highConfidence: true },

  { name: "Discord Bot Token", pattern: DISCORD_BOT_TOKEN, minLength: 40, allowsSpaces: false, highConfidence: true },
  { name: "Discord Webhook URL", pattern: DISCORD_WEBHOOK, minLength: 60, allowsSpaces: false, highConfidence: true },

  { name: "OpenAI API Key", pattern: OPENAI_API_KEY, minLength: 40, allowsSpaces: false, highConfidence: true },
  { name: "OpenAI API Key (New Format)", pattern: OPENAI_API_KEY_NEW, minLength: 40, allowsSpaces: false, highConfidence: true },
  { name: "Anthropic API Key", pattern: ANTHROPIC_API_KEY, minLength: 80, allowsSpaces: false, highConfidence: true },

  { name: "NPM Token", pattern: NPM_TOKEN, minLength: 36, allowsSpaces: false, highConfidence: true },
  { name: "PyPI Token", pattern: PYPI_TOKEN, minLength: 50, allowsSpaces: false, highConfidence: true },

  // Heroku keys use UUID format which could false-positive, so not marked high-confidence
  { name: "Heroku API Key", pattern: HEROKU_API_KEY, minLength: 30, allowsSpaces: false },

  { name: "RSA Private Key", pattern: RSA_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },
  { name: "OpenSSH Private Key", pattern: OPENSSH_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },
  { name: "DSA Private Key", pattern: DSA_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },
  { name: "EC Private Key", pattern: EC_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },
  { name: "PGP Private Key", pattern: PGP_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },
  { name: "Generic Private Key", pattern: GENERIC_PRIVATE_KEY, minLength: 20, allowsSpaces: true, highConfidence: true },

  { name: "MongoDB Connection String", pattern: MONGODB_URI, minLength: 20, allowsSpaces: false, highConfidence: true },
  { name: "PostgreSQL Connection String", pattern: POSTGRES_URI, minLength: 20, allowsSpaces: false, highConfidence: true },
  { name: "MySQL Connection String", pattern: MYSQL_URI, minLength: 20, allowsSpaces: false, highConfidence: true },
  { name: "Redis Connection String", pattern: REDIS_URI, minLength: 15, allowsSpaces: false, highConfidence: true },

  { name: "Password in URL", pattern: PASSWORD_IN_URL, minLength: 15, allowsSpaces: false, highConfidence: true },

  // Generic patterns below are not high-confidence because they match common
  // code patterns. They're checked against SAFE_PATTERNS to reduce false positives.
  { name: "Bearer Token", pattern: BEARER_TOKEN, minLength: 15, allowsSpaces: false },
  { name: "Basic Auth Header", pattern: BASIC_AUTH, minLength: 20, allowsSpaces: false },
  { name: "API Key Assignment", pattern: API_KEY_ASSIGNMENT, minLength: 20, allowsSpaces: false },
  { name: "Secret Assignment", pattern: SECRET_ASSIGNMENT, minLength: 12, allowsSpaces: false },
];

/**
 * Patterns that should NOT trigger detection. These are applied to:
 * 1. Entropy-based detection (to avoid flagging UUIDs, hashes, etc.)
 * 2. Low-confidence pattern matches (to avoid flagging "password=test123")
 *
 * High-confidence patterns (with specific prefixes like "ghp_") bypass these
 * checks since their format is unambiguous.
 */
export const SAFE_PATTERNS: RegExp[] = [
  /^https?:\/\/[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9./_\-?&=#%]*)?$/,  // URLs without credentials
  /^\.\.?\/[a-zA-Z0-9_\-./]+$/,                                 // Relative file paths
  /^\/[a-zA-Z0-9_\-./]+$/,                                      // Absolute Unix paths
  /^[a-zA-Z]:\\[a-zA-Z0-9_\-\\./]+$/,                           // Windows paths
  /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,         // Email addresses
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,  // UUIDs
  /^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?$/,   // Semver
  /^(?:xxx+|your[_-]?(?:api[_-]?)?key|placeholder|example|test|demo|sample)/i,  // Placeholders
  /^[0-9a-f]{40}$/i,                                            // Git SHA-1
  /^[0-9a-f]{64}$/i,                                            // SHA-256
  /^@[a-z0-9-]+\/[a-z0-9-]+$/,                                  // npm scoped packages
];

export const MIN_SCAN_LENGTH = 10;

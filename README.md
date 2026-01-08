# opencode-secret-protect

> **Warning**
> This project is in **alpha** and has not been extensively tested in real-world environments. Use at your own risk and please report any issues you encounter.

An OpenCode plugin that protects against secret leakage in AI tool calls.

## Features

- **Pattern-based detection**: Detects 40+ types of secrets including:
  - AWS credentials (Access Key ID, Secret Access Key)
  - GitHub tokens (PAT, Fine-grained, OAuth, App tokens)
  - GitLab tokens
  - Slack tokens and webhooks
  - JWT tokens
  - Google API keys and OAuth tokens
  - Stripe keys
  - SendGrid, Twilio, Discord tokens
  - OpenAI and Anthropic API keys
  - NPM and PyPI tokens
  - Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
  - Private keys (RSA, SSH, PGP, EC)
  - Passwords in URLs
  - And more...

- **Entropy-based detection**: Catches high-entropy strings that might be secrets even if they don't match known patterns

- **Safe pattern exclusions**: Reduces false positives by ignoring:
  - URLs without credentials
  - File paths
  - Email addresses
  - UUIDs
  - Semantic versions
  - Git SHAs

## Installation

### From npm (recommended)

Add to your `opencode.json`:

```json
{
  "plugin": ["opencode-secret-protect"]
}
```

### Local plugin

Copy the plugin source to `.opencode/plugin/` in your project:

```bash
cp -r src/* .opencode/plugin/
```

## How it works

The plugin hooks into OpenCode's tool execution via `tool.execute.after`, scanning tool output for these tools:
- `read`: Scans file contents
- `bash`: Scans command output
- `grep`: Scans search results

If a secret is detected in the output, it is **replaced** with a warning message to prevent the secret from entering the AI's context.

## Configuration

The plugin can be configured through the plugin context. Default settings:

```typescript
{
  // Tools to scan after execution
  scanToolsAfter: ["read", "bash", "grep"],

  // Entropy threshold (higher = fewer false positives)
  entropyThreshold: 4.5,

  // Enable entropy-based detection
  enableEntropyDetection: true,

  // Custom patterns to allow (regex strings)
  allowPatterns: [],
}
```

## Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck
```

## License

MIT

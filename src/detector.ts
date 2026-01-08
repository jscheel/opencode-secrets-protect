import { SECRET_PATTERNS, SAFE_PATTERNS, MIN_SCAN_LENGTH } from "./patterns.ts";
import { findHighEntropyToken, DEFAULT_ENTROPY_THRESHOLD } from "./entropy.ts";

export interface DetectionResult {
  found: boolean;
  secretType?: string;
  matchedPattern?: string;
  location?: {
    start: number;
    end: number;
  };
}

export interface DetectorOptions {
  /**
   * Entropy threshold for high-entropy string detection
   * Higher values = fewer false positives, may miss some secrets
   * @default 4.5
   */
  entropyThreshold?: number;

  /**
   * Enable entropy-based detection in addition to pattern matching
   * @default true
   */
  enableEntropyDetection?: boolean;

  /**
   * Custom patterns to ignore (regex strings)
   */
  allowPatterns?: string[];
}

function isSafeContent(content: string, customAllowPatterns?: string[]): boolean {
  for (const pattern of SAFE_PATTERNS) {
    if (pattern.test(content)) {
      return true;
    }
  }

  if (customAllowPatterns) {
    for (const patternStr of customAllowPatterns) {
      try {
        const pattern = new RegExp(patternStr);
        if (pattern.test(content)) {
          return true;
        }
      } catch {
        // Invalid regex, skip
      }
    }
  }

  return false;
}

function checkPatterns(
  content: string,
  options: DetectorOptions
): DetectionResult | null {
  for (const secretPattern of SECRET_PATTERNS) {
    if (content.length < secretPattern.minLength) {
      continue;
    }

    const match = secretPattern.pattern.exec(content);
    if (match) {
      const matchedText = match[0];

      if (!secretPattern.allowsSpaces && matchedText.includes(" ")) {
        continue;
      }

      // Low-confidence patterns (generic assignments like "secret=xxx") check against
      // safe patterns to reduce false positives. High-confidence patterns (specific
      // prefixes like "ghp_", "AKIA") skip this since their format is unambiguous.
      if (!secretPattern.highConfidence && isSafeContent(matchedText, options.allowPatterns)) {
        continue;
      }

      // Even high-confidence patterns respect user-defined allowPatterns
      if (secretPattern.highConfidence && options.allowPatterns) {
        let isAllowed = false;
        for (const patternStr of options.allowPatterns) {
          try {
            const pattern = new RegExp(patternStr);
            if (pattern.test(matchedText)) {
              isAllowed = true;
              break;
            }
          } catch {
            // Invalid regex, skip
          }
        }
        if (isAllowed) {
          continue;
        }
      }

      return {
        found: true,
        secretType: secretPattern.name,
        matchedPattern: maskSecret(matchedText),
        location: {
          start: match.index,
          end: match.index + matchedText.length,
        },
      };
    }
  }

  return null;
}

function checkEntropy(
  content: string,
  options: DetectorOptions
): DetectionResult | null {
  if (options.enableEntropyDetection === false) {
    return null;
  }

  const threshold = options.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
  const highEntropyToken = findHighEntropyToken(content, threshold);

  if (highEntropyToken) {
    if (isSafeContent(highEntropyToken, options.allowPatterns)) {
      return null;
    }

    return {
      found: true,
      secretType: "High Entropy String (potential secret)",
      matchedPattern: maskSecret(highEntropyToken),
    };
  }

  return null;
}

function maskSecret(secret: string): string {
  if (secret.length <= 12) {
    return "***";
  }
  return `${secret.slice(0, 4)}***${secret.slice(-4)}`;
}

export function detectSecrets(
  content: string,
  options: DetectorOptions = {}
): DetectionResult {
  if (content.length < MIN_SCAN_LENGTH) {
    return { found: false };
  }

  const patternResult = checkPatterns(content, options);
  if (patternResult) {
    return patternResult;
  }

  const entropyResult = checkEntropy(content, options);
  if (entropyResult) {
    return entropyResult;
  }

  return { found: false };
}

export function scanContents(
  contents: string[],
  options: DetectorOptions = {}
): DetectionResult {
  for (const content of contents) {
    const result = detectSecrets(content, options);
    if (result.found) {
      return result;
    }
  }
  return { found: false };
}

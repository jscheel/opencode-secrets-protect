/**
 * Shannon entropy measures the average information content per character.
 * Returns 0 for uniform strings ("aaaa") and increases with randomness.
 * Typical values: ~3.5 for English text, ~4-6 for random alphanumeric secrets.
 */
export function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of data) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = data.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

interface CharacterAnalysis {
  letters: number;
  uppercase: number;
  lowercase: number;
  digits: number;
  symbols: number;
  caseSwitches: number;
}

function analyzeCharacters(data: string): CharacterAnalysis {
  let letters = 0;
  let uppercase = 0;
  let lowercase = 0;
  let digits = 0;
  let symbols = 0;
  let caseSwitches = 0;
  let previousWasUpper = false;

  for (let i = 0; i < data.length; i++) {
    const char = data[i]!;
    const code = char.charCodeAt(0);

    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
      letters++;
      const isUpper = code >= 65 && code <= 90;
      if (isUpper) {
        uppercase++;
        if (i > 0 && !previousWasUpper) caseSwitches++;
        previousWasUpper = true;
      } else {
        lowercase++;
        if (i > 0 && previousWasUpper) caseSwitches++;
        previousWasUpper = false;
      }
    } else if (code >= 48 && code <= 57) {
      digits++;
    } else if (char !== " " && char !== "\t" && char !== "\n") {
      symbols++;
    }
  }

  return { letters, uppercase, lowercase, digits, symbols, caseSwitches };
}

/**
 * Adjusted entropy boosts the base Shannon entropy based on character class diversity
 * (mixed case, symbols, digits) which are common characteristics of secrets.
 */
export function calculateAdjustedEntropy(data: string): number {
  const baseEntropy = shannonEntropy(data);
  const len = data.length;
  if (len === 0) return 0;

  const analysis = analyzeCharacters(data);

  // Frequent case switches (e.g., "aBcDeF") strongly indicate generated secrets
  let caseEntropyBoost = 0;
  if (analysis.uppercase > 0 && analysis.lowercase > 0 && analysis.letters > 0) {
    caseEntropyBoost = (analysis.caseSwitches / analysis.letters) * 2.0;
  }

  const symbolEntropyBoost = analysis.symbols > 0 ? (analysis.symbols / len) * 1.5 : 0;
  const digitEntropyBoost = analysis.digits > 0 ? (analysis.digits / len) : 0;

  // The 2.5 multiplier on case boost is empirically tuned to catch API keys
  // while avoiding false positives on camelCase identifiers
  return baseEntropy + caseEntropyBoost * 2.5 + symbolEntropyBoost + digitEntropyBoost;
}

export const DEFAULT_ENTROPY_THRESHOLD = 4.5;

export const MIN_ENTROPY_TOKEN_LENGTH = 16;

export function isHighEntropy(
  data: string,
  threshold: number = DEFAULT_ENTROPY_THRESHOLD
): boolean {
  if (data.length < MIN_ENTROPY_TOKEN_LENGTH) return false;

  const entropy = calculateAdjustedEntropy(data);
  return entropy > threshold;
}

export function findHighEntropyToken(
  content: string,
  threshold: number = DEFAULT_ENTROPY_THRESHOLD
): string | null {
  const tokens = content.split(/[\s.,;:'"=\[\]{}()<>|/\\]+/);

  for (const token of tokens) {
    if (token.length >= MIN_ENTROPY_TOKEN_LENGTH && isHighEntropy(token, threshold)) {
      return token;
    }
  }

  return null;
}

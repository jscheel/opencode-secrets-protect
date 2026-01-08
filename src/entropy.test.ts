import { describe, expect, it } from "bun:test";
import {
  shannonEntropy,
  calculateAdjustedEntropy,
  isHighEntropy,
  findHighEntropyToken,
} from "./entropy.ts";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated character", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("returns 1 for two different characters with equal frequency", () => {
    expect(shannonEntropy("ab")).toBe(1);
  });

  it("returns higher entropy for more diverse strings", () => {
    const lowEntropy = shannonEntropy("aaaabbbb");
    const highEntropy = shannonEntropy("abcdefgh");
    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });

  it("returns expected entropy for known strings", () => {
    const entropy = shannonEntropy("aab");
    expect(entropy).toBeCloseTo(0.918, 2);
  });
});

describe("calculateAdjustedEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(calculateAdjustedEntropy("")).toBe(0);
  });

  it("returns low entropy for repeated lowercase", () => {
    const entropy = calculateAdjustedEntropy("aaaaaaaaaaaaaaaa");
    expect(entropy).toBeLessThan(2.0);
  });

  it("returns moderate entropy for mixed case alternating", () => {
    const entropy = calculateAdjustedEntropy("AbCdEfGhIjK");
    expect(entropy).toBeGreaterThan(5.0);
  });

  it("returns higher entropy for secret-like strings", () => {
    const entropy = calculateAdjustedEntropy("AKIaSyD9mP+e2KqZ2S");
    expect(entropy).toBeGreaterThan(6.0);
  });

  it("applies digit boost", () => {
    const withoutDigits = calculateAdjustedEntropy("abcdefghijklmnop");
    const withDigits = calculateAdjustedEntropy("abcd1234ijklmnop");
    expect(withDigits).toBeGreaterThan(withoutDigits);
  });

  it("applies symbol boost", () => {
    const withoutSymbols = calculateAdjustedEntropy("abcdefghijklmnop");
    const withSymbols = calculateAdjustedEntropy("abcd!@#$ijklmnop");
    expect(withSymbols).toBeGreaterThan(withoutSymbols);
  });
});

describe("isHighEntropy", () => {
  it("returns false for short strings", () => {
    expect(isHighEntropy("abc123")).toBe(false);
  });

  it("returns false for low entropy strings", () => {
    expect(isHighEntropy("aaaaaaaaaaaaaaaaaaaaaa")).toBe(false);
  });

  it("returns true for high entropy strings", () => {
    expect(isHighEntropy("aB3xK9mZ2qW4rT8yU1oP5nL7jH0gF6dS")).toBe(true);
  });

  it("respects custom threshold", () => {
    const testString = "aB3xK9mZ2qW4rT8yU1oP5nL7jH0gF6dS";
    expect(isHighEntropy(testString, 3.0)).toBe(true);
    expect(isHighEntropy(testString, 12.0)).toBe(false);
  });
});

describe("findHighEntropyToken", () => {
  it("returns null for content without high entropy tokens", () => {
    expect(findHighEntropyToken("hello world foo bar")).toBeNull();
  });

  it("returns null when all tokens are too short", () => {
    expect(findHighEntropyToken("a b c d e f")).toBeNull();
  });

  it("finds high entropy token in mixed content", () => {
    const secretToken = "aB3xK9mZ2qW4rT8yU1oP";
    const content = `const apiKey = "${secretToken}";`;
    
    const result = findHighEntropyToken(content, 4.0);
    expect(result).not.toBeNull();
  });

  it("respects threshold parameter", () => {
    const content = "some text with aB3xK9mZ2qW4rT8yU1oP embedded";
    expect(findHighEntropyToken(content, 3.0)).not.toBeNull();
    expect(findHighEntropyToken(content, 10.0)).toBeNull();
  });
});

/**
 * OpenCode Secret Protection Plugin
 *
 * Protects against secret leakage by scanning tool inputs and outputs
 * for sensitive data like API keys, tokens, and credentials.
 */

import type { Plugin } from "@opencode-ai/plugin";
import { detectSecrets, type DetectorOptions } from "./detector.ts";

export interface SecretProtectConfig extends DetectorOptions {
  /**
   * Tools to scan for secrets in their output (after execution)
   * @default ["read", "bash", "grep"]
   */
  scanToolsAfter?: string[];

  /**
   * Enable/disable the plugin
   * @default true
   */
  enabled?: boolean;
}

const DEFAULT_CONFIG: Required<SecretProtectConfig> = {
  scanToolsAfter: ["read", "bash", "grep"],
  enabled: true,
  entropyThreshold: 4.5,
  enableEntropyDetection: true,
  allowPatterns: [],
};

const SECRET_DETECTED_WARNING = `[SECRET PROTECTION] This tool call resulted in potential secret exposure.

For security reasons, the output has been blocked. Do not attempt to exfiltrate secrets.

If this is a false positive, you can:
1. Add the pattern to 'allowPatterns' in your plugin config
2. Adjust the 'entropyThreshold' setting (higher = fewer false positives)
3. Disable entropy detection with 'enableEntropyDetection: false'`;

function extractStringsFromOutput(output: string): string[] {
  return [output];
}

const SecretProtectPlugin: Plugin = async (_ctx) => {
  const config: Required<SecretProtectConfig> = {
    ...DEFAULT_CONFIG,
  };

  if (!config.enabled) {
    return {};
  }

  return {
    // Scan AFTER execution to prevent secrets from being returned to the AI context.
    // We overwrite the output rather than throw since the tool already executed.
    "tool.execute.after": async (input, output) => {
      const { tool } = input;

      if (!config.scanToolsAfter.includes(tool)) {
        return;
      }

      const contents = extractStringsFromOutput(output.output);

      for (const content of contents) {
        const detection = detectSecrets(content, {
          entropyThreshold: config.entropyThreshold,
          enableEntropyDetection: config.enableEntropyDetection,
          allowPatterns: config.allowPatterns,
        });

        if (detection.found) {
          output.output = `${SECRET_DETECTED_WARNING}\n\nDetected: ${detection.secretType}\nPattern: ${detection.matchedPattern}`;
          return;
        }
      }
    },
  };
};

export default SecretProtectPlugin;

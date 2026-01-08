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
   * Tools to scan for secrets in their arguments (before execution)
   * @default ["write", "edit", "bash"]
   */
  scanToolsBefore?: string[];

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
  scanToolsBefore: ["write", "edit", "bash"],
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

function getContentToScanBefore(
  tool: string,
  args: Record<string, unknown>
): string[] {
  const contents: string[] = [];

  switch (tool) {
    case "write":
      if (typeof args.content === "string") {
        contents.push(args.content);
      }
      break;

    case "edit":
      if (typeof args.newString === "string") {
        contents.push(args.newString);
      }
      break;

    case "bash":
      if (typeof args.command === "string") {
        contents.push(args.command);
      }
      break;

    default:
      for (const value of Object.values(args)) {
        if (typeof value === "string") {
          contents.push(value);
        }
      }
  }

  return contents;
}

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
    // Scan BEFORE execution to prevent the AI from writing secrets to files or
    // exfiltrating them via bash commands. Throwing here blocks the tool entirely.
    "tool.execute.before": async (input, output) => {
      const { tool } = input;

      if (!config.scanToolsBefore.includes(tool)) {
        return;
      }

      const contents = getContentToScanBefore(tool, output.args);

      for (const content of contents) {
        const detection = detectSecrets(content, {
          entropyThreshold: config.entropyThreshold,
          enableEntropyDetection: config.enableEntropyDetection,
          allowPatterns: config.allowPatterns,
        });

        if (detection.found) {
          throw new Error(
            `${SECRET_DETECTED_WARNING}\n\nDetected: ${detection.secretType}\nPattern: ${detection.matchedPattern}`
          );
        }
      }
    },

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

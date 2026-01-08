import { describe, expect, it } from "bun:test";
import { detectSecrets } from "./detector.ts";

describe("detectSecrets", () => {
  describe("AWS credentials", () => {
    it("detects AWS access key ID", () => {
      const result = detectSecrets("const key = 'AKIAIOSFODNN7EXAMPLE';");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("AWS Access Key ID");
    });

    it("detects AWS access key in various formats", () => {
      const testCases = [
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'",
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
      ];

      for (const testCase of testCases) {
        const result = detectSecrets(testCase);
        expect(result.found).toBe(true);
      }
    });
  });

  describe("GitHub tokens", () => {
    it("detects GitHub personal access token", () => {
      const result = detectSecrets("ghp_1234567890abcdefghijklmnopqrstuvwxyz");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("GitHub Personal Access Token");
    });

    it("detects GitHub fine-grained token", () => {
      const result = detectSecrets("github_pat_11ABCDEF0123456789abcdef");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("GitHub Fine-Grained Token");
    });

    it("detects GitHub OAuth token", () => {
      const result = detectSecrets("gho_1234567890abcdefghijklmnopqrstuvwxyz");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("GitHub OAuth Token");
    });
  });

  describe("Slack tokens", () => {
    it("detects Slack bot token", () => {
      const result = detectSecrets("xoxb-1234567890-1234567890-abcdefghijklmnop");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("Slack Token");
    });

    it("detects Slack webhook URL", () => {
      const result = detectSecrets(
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      );
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("Slack Webhook URL");
    });
  });

  describe("JWT tokens", () => {
    it("detects JWT", () => {
      // This is a test JWT (not a real secret)
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const result = detectSecrets(jwt);
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("JSON Web Token (JWT)");
    });
  });

  describe("API keys", () => {
    it("detects Google API key", () => {
      const result = detectSecrets("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("Google API Key");
    });

    it("detects Stripe secret key", () => {
      const result = detectSecrets("sk_live_1234567890abcdefghijklmno");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("Stripe Secret Key");
    });

    it("detects SendGrid API key", () => {
      const result = detectSecrets(
        "SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG"
      );
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("SendGrid API Key");
    });
  });

  describe("Private keys", () => {
    it("detects RSA private key", () => {
      const result = detectSecrets("-----BEGIN RSA PRIVATE KEY-----");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("RSA Private Key");
    });

    it("detects OpenSSH private key", () => {
      const result = detectSecrets("-----BEGIN OPENSSH PRIVATE KEY-----");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("OpenSSH Private Key");
    });

    it("detects PGP private key", () => {
      const result = detectSecrets("-----BEGIN PGP PRIVATE KEY BLOCK-----");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("PGP Private Key");
    });
  });

  describe("Database URIs", () => {
    it("detects MongoDB connection string", () => {
      const result = detectSecrets(
        "mongodb+srv://username:password@cluster.mongodb.net/database"
      );
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("MongoDB Connection String");
    });

    it("detects PostgreSQL connection string", () => {
      const result = detectSecrets(
        "postgres://user:secret@localhost:5432/mydb"
      );
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("PostgreSQL Connection String");
    });
  });

  describe("Passwords in URLs", () => {
    it("detects password in URL", () => {
      const result = detectSecrets("https://admin:supersecret@example.com/api");
      expect(result.found).toBe(true);
      expect(result.secretType).toBe("Password in URL");
    });
  });

  describe("Safe patterns (should not detect)", () => {
    it("does not flag simple URLs without credentials", () => {
      const result = detectSecrets("https://api.example.com/v1/users");
      expect(result.found).toBe(false);
    });

    it("does not flag file paths", () => {
      const result = detectSecrets("./src/components/Button.tsx");
      expect(result.found).toBe(false);
    });

    it("does not flag email addresses", () => {
      const result = detectSecrets("user@example.com");
      expect(result.found).toBe(false);
    });

    it("does not flag UUIDs", () => {
      const result = detectSecrets("550e8400-e29b-41d4-a716-446655440000");
      expect(result.found).toBe(false);
    });

    it("does not flag semantic versions", () => {
      const result = detectSecrets("v1.2.3-beta.1");
      expect(result.found).toBe(false);
    });

    it("does not flag placeholder values", () => {
      const result = detectSecrets("your-api-key-here");
      expect(result.found).toBe(false);
    });

    it("does not flag short strings", () => {
      const result = detectSecrets("hello");
      expect(result.found).toBe(false);
    });
  });

  describe("Options", () => {
    it("respects allowPatterns option", () => {
      const result = detectSecrets("ghp_1234567890abcdefghijklmnopqrstuvwxyz", {
        allowPatterns: ["ghp_.*"],
      });
      expect(result.found).toBe(false);
    });

    it("respects entropyThreshold option", () => {
      const highEntropyString = "aB3xK9mZ2qW4rT8yU1oP5nL7jH0gF6dS";
      
      const resultLowThreshold = detectSecrets(highEntropyString, {
        enableEntropyDetection: true,
        entropyThreshold: 4.0,
      });
      
      const resultHighThreshold = detectSecrets(highEntropyString, {
        enableEntropyDetection: true,
        entropyThreshold: 12.0,
      });

      expect(resultLowThreshold.found).toBe(true);
      expect(resultHighThreshold.found).toBe(false);
    });

    it("respects enableEntropyDetection option", () => {
      const highEntropyString = "qW3rT5yU7iO9pA1sD2fG4hJ6kL8zX0cV";
      
      const resultEnabled = detectSecrets(highEntropyString, {
        enableEntropyDetection: true,
        entropyThreshold: 4.0,
      });
      
      const resultDisabled = detectSecrets(highEntropyString, {
        enableEntropyDetection: false,
      });

      expect(resultEnabled.found).toBe(true);
      expect(resultDisabled.found).toBe(false);
    });
  });
});

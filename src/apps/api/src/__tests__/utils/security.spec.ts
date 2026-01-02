import {
  encryptData,
  decryptData,
  generateToken,
  hashPassword,
  verifyPassword,
} from "../../utils/security";

describe("Security Utilities", () => {
  describe("encryptData and decryptData", () => {
    it("should encrypt and decrypt data", () => {
      const originalData = "sensitive information";

      const encrypted = encryptData(originalData);

      expect(encrypted).not.toBe(originalData);
      expect(encrypted).toBeDefined();

      const decrypted = decryptData(encrypted);

      expect(decrypted).toBe(originalData);
    });

    it("should produce different ciphers for same data", () => {
      const data = "test data";

      const encrypted1 = encryptData(data);
      const encrypted2 = encryptData(data);

      expect(encrypted1).not.toBe(encrypted2); // Should use random IV
    });

    it("should handle special characters", () => {
      const data = '<script>alert("xss")</script>';

      const encrypted = encryptData(data);
      const decrypted = decryptData(encrypted);

      expect(decrypted).toBe(data);
    });
  });

  describe("generateToken", () => {
    it("should generate unique tokens", () => {
      const token1 = generateToken();
      const token2 = generateToken();

      expect(token1).not.toBe(token2);
    });

    it("should generate tokens of correct length", () => {
      const token = generateToken(32);

      expect(token.length).toBe(32 * 2); // hex encoding doubles length
    });

    it("should generate valid hex strings", () => {
      const token = generateToken();

      expect(/^[a-f0-9]+$/.test(token)).toBe(true);
    });
  });

  describe("hashPassword and verifyPassword", () => {
    it("should hash password", () => {
      const password = "SecurePassword123!";

      const hashed = hashPassword(password);

      expect(hashed).not.toBe(password);
      expect(hashed.length).toBeGreaterThan(password.length);
    });

    it("should verify correct password", () => {
      const password = "SecurePassword123!";

      const hashed = hashPassword(password);
      const isValid = verifyPassword(password, hashed);

      expect(isValid).toBe(true);
    });

    it("should reject incorrect password", () => {
      const password = "SecurePassword123!";
      const wrongPassword = "WrongPassword123!";

      const hashed = hashPassword(password);
      const isValid = verifyPassword(wrongPassword, hashed);

      expect(isValid).toBe(false);
    });

    it("should produce different hashes for same password", () => {
      const password = "test";

      const hash1 = hashPassword(password);
      const hash2 = hashPassword(password);

      expect(hash1).not.toBe(hash2); // Salted hashing
    });

    it("should handle special characters in password", () => {
      const password = '<script>alert("xss")</script>';

      const hashed = hashPassword(password);
      const isValid = verifyPassword(password, hashed);

      expect(isValid).toBe(true);
    });
  });
});

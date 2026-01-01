/**
 * End-to-End Encryption for Sensitive Data
 * Encrypts PII and sensitive shipment data at application level
 * before it hits the database.
 */

import crypto from "crypto";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits

export class DataEncryption {
  private masterKey: Buffer;

  constructor(masterKeyEnv: string = process.env.ENCRYPTION_MASTER_KEY || "") {
    if (!masterKeyEnv) {
      throw new Error("ENCRYPTION_MASTER_KEY environment variable is required");
    }

    // Derive a consistent key from the master key
    this.masterKey = crypto.pbkdf2Sync(
      masterKeyEnv,
      "infamous-freight",
      100000,
      32,
      "sha256",
    );
  }

  /**
   * Encrypt a string value
   * Returns: salt + iv + encryptedData + authTag (all base64)
   */
  encrypt(plaintext: string): string {
    try {
      // Generate random salt and IV
      const salt = crypto.randomBytes(SALT_LENGTH);
      const iv = crypto.randomBytes(IV_LENGTH);

      // Derive a key from master key + salt (for additional security)
      const derivedKey = crypto.pbkdf2Sync(
        this.masterKey,
        salt,
        10000,
        32,
        "sha256",
      );

      // Create cipher
      const cipher = crypto.createCipheriv(
        ENCRYPTION_ALGORITHM,
        derivedKey,
        iv,
      );

      // Encrypt data
      let encrypted = cipher.update(plaintext, "utf8", "hex");
      encrypted += cipher.final("hex");

      // Get authentication tag
      const authTag = cipher.getAuthTag();

      // Combine: salt + iv + encrypted + authTag
      const combined = Buffer.concat([
        salt,
        iv,
        Buffer.from(encrypted, "hex"),
        authTag,
      ]);

      // Return as base64 for database storage
      return combined.toString("base64");
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt a string value encrypted with encrypt()
   */
  decrypt(encryptedData: string): string {
    try {
      // Convert from base64
      const combined = Buffer.from(encryptedData, "base64");

      // Extract components
      const salt = combined.slice(0, SALT_LENGTH);
      const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
      const authTag = combined.slice(combined.length - AUTH_TAG_LENGTH);
      const encrypted = combined.slice(
        SALT_LENGTH + IV_LENGTH,
        combined.length - AUTH_TAG_LENGTH,
      );

      // Derive key using the stored salt
      const derivedKey = crypto.pbkdf2Sync(
        this.masterKey,
        salt,
        10000,
        32,
        "sha256",
      );

      // Create decipher
      const decipher = crypto.createDecipheriv(
        ENCRYPTION_ALGORITHM,
        derivedKey,
        iv,
      );

      // Set auth tag for verification
      decipher.setAuthTag(authTag);

      // Decrypt
      let plaintext = decipher.update(encrypted.toString("hex"), "hex", "utf8");
      plaintext += decipher.final("utf8");

      return plaintext;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Hash a value (for comparisons without revealing plaintext)
   * Useful for searching encrypted data
   */
  hash(value: string): string {
    return crypto
      .createHmac("sha256", this.masterKey)
      .update(value)
      .digest("hex");
  }

  /**
   * Encrypt multiple fields from an object
   */
  encryptFields<T extends Record<string, any>>(
    data: T,
    fieldsToEncrypt: (keyof T)[],
  ): T {
    const encrypted = { ...data };

    for (const field of fieldsToEncrypt) {
      if (encrypted[field] && typeof encrypted[field] === "string") {
        encrypted[field] = this.encrypt(encrypted[field]);
      }
    }

    return encrypted;
  }

  /**
   * Decrypt multiple fields from an object
   */
  decryptFields<T extends Record<string, any>>(
    data: T,
    fieldsToDecrypt: (keyof T)[],
  ): T {
    const decrypted = { ...data };

    for (const field of fieldsToDecrypt) {
      if (decrypted[field] && typeof decrypted[field] === "string") {
        try {
          decrypted[field] = this.decrypt(decrypted[field]);
        } catch {
          // Field not encrypted, skip
        }
      }
    }

    return decrypted;
  }
}

// Singleton instance
let encryptionInstance: DataEncryption | null = null;

export function getEncryption(): DataEncryption {
  if (!encryptionInstance) {
    encryptionInstance = new DataEncryption();
  }
  return encryptionInstance;
}

/**
 * Example usage in Prisma:
 *
 * // Before saving
 * const encrypted = getEncryption().encryptFields(shipment, ['origin', 'destination']);
 * await prisma.shipment.create({ data: encrypted });
 *
 * // After retrieving
 * const encrypted = await prisma.shipment.findUnique({ where: { id } });
 * const decrypted = getEncryption().decryptFields(encrypted, ['origin', 'destination']);
 *
 * // For searching on encrypted fields, use the hash
 * const originHash = getEncryption().hash('New York');
 * await prisma.shipment.findMany({
 *   where: { originHash }
 * });
 */

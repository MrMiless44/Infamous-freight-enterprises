import crypto from "crypto";
import bcrypt from "bcrypt";

const SECRET =
  process.env.SECURITY_SECRET || "dev-secret-key-32chars-dev-secret-key";

export function encryptData(data: string): string {
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(SECRET).digest();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(data, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decryptData(payload: string): string {
  const [ivHex, tagHex, encryptedHex] = payload.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const key = crypto.createHash("sha256").update(SECRET).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

export function generateToken(length = 16): string {
  return crypto.randomBytes(length).toString("hex");
}

export function hashPassword(password: string): string {
  const saltRounds = 8;
  return bcrypt.hashSync(password, saltRounds);
}

export function verifyPassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}

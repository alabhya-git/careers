const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const { JWT_EXPIRY, OTP_STEP_SECONDS, OTP_WINDOW } = require("./config");

function normalizePemValue(rawValue) {
  const normalized = String(rawValue || "").trim();
  if (!normalized) {
    return "";
  }
  return normalized.replace(/\\n/g, "\n");
}

function normalizeResumeKey(rawKey) {
  if (!rawKey) {
    return crypto
      .createHash("sha256")
      .update("development-only-resume-key-change-me")
      .digest();
  }

  if (/^[a-fA-F0-9]{64}$/.test(rawKey)) {
    return Buffer.from(rawKey, "hex");
  }

  const base64Buffer = Buffer.from(rawKey, "base64");
  if (base64Buffer.length !== 32) {
    throw new Error(
      "RESUME_ENCRYPTION_KEY must be 32-byte base64 or a 64-character hex value."
    );
  }

  return base64Buffer;
}

const RESUME_KEY = normalizeResumeKey(process.env.RESUME_ENCRYPTION_KEY);
const JWT_PRIVATE_KEY = normalizePemValue(process.env.JWT_PRIVATE_KEY);
const JWT_PUBLIC_KEY = normalizePemValue(process.env.JWT_PUBLIC_KEY);
const AUDIT_LOG_PRIVATE_KEY = normalizePemValue(process.env.AUDIT_LOG_PRIVATE_KEY);
const AUDIT_LOG_PUBLIC_KEY = normalizePemValue(process.env.AUDIT_LOG_PUBLIC_KEY);

function getJwtSecret() {
  return process.env.JWT_SECRET || "development-jwt-secret-change-me";
}

function isJwtPkiEnabled() {
  return Boolean(JWT_PRIVATE_KEY && JWT_PUBLIC_KEY);
}

function isAuditPkiEnabled() {
  return Boolean(AUDIT_LOG_PRIVATE_KEY && AUDIT_LOG_PUBLIC_KEY);
}

function hashPassword(password) {
  return bcrypt.hashSync(password, 12);
}

function verifyPassword(password, passwordHash) {
  return bcrypt.compareSync(password, passwordHash);
}

function generateOtpSecret() {
  return speakeasy.generateSecret({ length: 20 }).base32;
}

function generateTotp(secret) {
  return speakeasy.totp({
    secret,
    encoding: "base32",
    step: OTP_STEP_SECONDS,
    digits: 6,
  });
}

function verifyTotp(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: String(token || "").trim(),
    step: OTP_STEP_SECONDS,
    window: OTP_WINDOW,
    digits: 6,
  });
}

function signAuthToken(payload) {
  if (isJwtPkiEnabled()) {
    return jwt.sign(payload, JWT_PRIVATE_KEY, {
      expiresIn: JWT_EXPIRY,
      algorithm: "RS256",
    });
  }
  return jwt.sign(payload, getJwtSecret(), { expiresIn: JWT_EXPIRY });
}

function verifyAuthToken(token) {
  if (isJwtPkiEnabled()) {
    try {
      return jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
    } catch (error) {
      // Compatibility path for older HS256 tokens minted before PKI rollout.
      return jwt.verify(token, getJwtSecret(), { algorithms: ["HS256"] });
    }
  }
  return jwt.verify(token, getJwtSecret(), { algorithms: ["HS256"] });
}

function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", RESUME_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    algorithm: "aes-256-gcm",
    keyVersion: "v1",
  };
}

function decryptBuffer(ciphertext, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    RESUME_KEY,
    Buffer.from(iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(authTag, "base64"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacSha256(value, key) {
  return crypto.createHmac("sha256", key).update(value).digest("hex");
}

function getAuditSigningKey() {
  return process.env.AUDIT_LOG_SIGNING_KEY || "development-audit-signing-key-change-me";
}

function signWithPrivateKey(value, privateKey) {
  return crypto
    .sign("sha256", Buffer.from(value), privateKey)
    .toString("base64");
}

function verifyWithPublicKey(value, signature, publicKey) {
  try {
    return crypto.verify(
      "sha256",
      Buffer.from(value),
      publicKey,
      Buffer.from(String(signature || ""), "base64")
    );
  } catch (error) {
    return false;
  }
}

function signAuditChainLink(value) {
  if (isAuditPkiEnabled()) {
    return signWithPrivateKey(value, AUDIT_LOG_PRIVATE_KEY);
  }
  return hmacSha256(value, getAuditSigningKey());
}

function verifyAuditChainLink(value, signature, chainVersion) {
  if (chainVersion === "PKI_RSA_SHA256_V3") {
    if (!isAuditPkiEnabled()) {
      return false;
    }
    return verifyWithPublicKey(value, signature, AUDIT_LOG_PUBLIC_KEY);
  }
  return signature === hmacSha256(value, getAuditSigningKey());
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateOtpSecret,
  generateTotp,
  verifyTotp,
  signAuthToken,
  verifyAuthToken,
  encryptBuffer,
  decryptBuffer,
  sha256,
  hmacSha256,
  getAuditSigningKey,
  isJwtPkiEnabled,
  isAuditPkiEnabled,
  signAuditChainLink,
  verifyAuditChainLink,
};

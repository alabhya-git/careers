const path = require("path");

const ROOT_DIR = path.join(__dirname, "..");
const DATA_DIR = path.join(ROOT_DIR, "data");
const STORAGE_DIR = path.join(ROOT_DIR, "storage");
const RESUME_DIR = path.join(STORAGE_DIR, "resumes");
const DB_FILE = path.join(DATA_DIR, "db.json");

module.exports = {
  ROOT_DIR,
  DATA_DIR,
  STORAGE_DIR,
  RESUME_DIR,
  DB_FILE,
  PORT: Number(process.env.PORT || 5000),
  CORS_ORIGIN: process.env.CORS_ORIGIN || "*",
  OTP_STEP_SECONDS: Number(process.env.OTP_STEP_SECONDS || 30),
  OTP_WINDOW: Number(process.env.OTP_WINDOW || 1),
  TOTP_ISSUER: process.env.TOTP_ISSUER || "Damera Corp. Careers Portal",
  JWT_EXPIRY: process.env.JWT_EXPIRY || "2h",
};

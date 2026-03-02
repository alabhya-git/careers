require("dotenv").config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const hpp = require("hpp");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");

const {
  PORT,
  CORS_ORIGIN,
  OTP_STEP_SECONDS,
  TOTP_ISSUER,
  RESUME_DIR,
} = require("./src/config");
const { appendAuditLog, verifyAuditChain } = require("./src/audit");
const { ensureDirectories, readDb, writeDb } = require("./src/store");
const {
  hashPassword,
  verifyPassword,
  generateOtpSecret,
  verifyTotp,
  signAuthToken,
  verifyAuthToken,
  encryptBuffer,
  decryptBuffer,
} = require("./src/security");

const app = express();

const PROFILE_PRIVACY_OPTIONS = new Set(["public", "connections", "private"]);
const ALLOWED_SELF_ROLES = new Set(["user", "recruiter"]);
const PASSWORD_POLICY =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,64}$/;
const TOTP_SETUP_QR_SIZE = 240;

const baseCorsOptions = {
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

if (CORS_ORIGIN === "*") {
  baseCorsOptions.origin = true;
} else {
  baseCorsOptions.origin = CORS_ORIGIN.split(",").map((item) => item.trim());
}

app.use(cors(baseCorsOptions));
app.use(helmet());
app.use(hpp());
app.use(express.json({ limit: "2mb" }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use("/api/auth", authLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (_, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const allowedMimeTypes = new Set([
      "application/pdf",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]);
    const allowedExtensions = new Set([".pdf", ".docx"]);

    if (
      allowedMimeTypes.has(file.mimetype) &&
      allowedExtensions.has(extension)
    ) {
      callback(null, true);
      return;
    }

    callback(new Error("Only PDF and DOCX files are allowed."));
  },
});

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeMobile(mobile) {
  return String(mobile || "").replace(/[^\d]/g, "");
}

function sanitizeText(value, maxLength = 255) {
  return String(value || "").trim().slice(0, maxLength);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidMobile(mobile) {
  return /^\d{10,15}$/.test(mobile);
}

function maskEmail(email) {
  const [prefix, domain] = String(email || "").split("@");
  if (!prefix || !domain) {
    return "hidden";
  }

  if (prefix.length <= 2) {
    return `${prefix[0] || "*"}*@${domain}`;
  }

  return `${prefix.slice(0, 2)}***@${domain}`;
}

function maskMobile(mobile) {
  const digits = normalizeMobile(mobile);
  if (digits.length < 4) {
    return "***";
  }

  return `${"*".repeat(Math.max(digits.length - 4, 1))}${digits.slice(-4)}`;
}

function normalizeTotpCode(value) {
  return String(value || "").replace(/\s+/g, "");
}

function ensureUserTotpState(user) {
  if (!user.totp || typeof user.totp !== "object") {
    user.totp = {};
  }

  if (typeof user.totp.secret !== "string") {
    user.totp.secret = "";
  }

  if (typeof user.totp.pendingSecret !== "string") {
    user.totp.pendingSecret = "";
  }

  if (
    user.totp.pendingIssuedAt !== null &&
    typeof user.totp.pendingIssuedAt !== "string"
  ) {
    user.totp.pendingIssuedAt = null;
  }

  if (
    user.totp.lastVerifiedAt !== null &&
    typeof user.totp.lastVerifiedAt !== "string"
  ) {
    user.totp.lastVerifiedAt = null;
  }

  if (typeof user.totp.isEnabled !== "boolean") {
    user.totp.isEnabled = Boolean(user.totp.secret);
  }

  if (user.totp.secret && !user.totp.isEnabled) {
    user.totp.isEnabled = true;
  }

  return user.totp;
}

function buildTotpSetupPayload(user, secret) {
  const accountName = user.email || user.id;
  const label = `${TOTP_ISSUER}:${accountName}`;
  const otpauthUrl =
    `otpauth://totp/${encodeURIComponent(label)}` +
    `?secret=${encodeURIComponent(secret)}` +
    `&issuer=${encodeURIComponent(TOTP_ISSUER)}` +
    `&algorithm=SHA1&digits=6&period=${OTP_STEP_SECONDS}`;
  const qrCodeUrl =
    `https://api.qrserver.com/v1/create-qr-code/?size=${TOTP_SETUP_QR_SIZE}x${TOTP_SETUP_QR_SIZE}` +
    `&data=${encodeURIComponent(otpauthUrl)}`;

  return {
    issuer: TOTP_ISSUER,
    accountName,
    manualEntryKey: secret,
    otpauthUrl,
    qrCodeUrl,
  };
}

function verifyUserTotp(user, code) {
  const totpState = ensureUserTotpState(user);
  if (!totpState.isEnabled || !totpState.secret) {
    return false;
  }

  return verifyTotp(totpState.secret, normalizeTotpCode(code));
}

function defaultPrivacySettings() {
  return {
    headline: "public",
    location: "connections",
    education: "connections",
    experience: "connections",
    skills: "public",
    bio: "public",
  };
}

function buildDefaultProfile(name) {
  return {
    name: sanitizeText(name, 80),
    headline: "",
    location: "",
    education: "",
    experience: "",
    skills: [],
    profilePicture: "",
    bio: "",
    privacy: defaultPrivacySettings(),
  };
}

function parseSkills(skillsInput) {
  if (Array.isArray(skillsInput)) {
    return skillsInput
      .map((item) => sanitizeText(item, 40))
      .filter(Boolean)
      .slice(0, 25);
  }

  if (typeof skillsInput === "string") {
    return skillsInput
      .split(",")
      .map((item) => sanitizeText(item, 40))
      .filter(Boolean)
      .slice(0, 25);
  }

  return [];
}

function safeResumeMetadata(resume) {
  if (!resume) {
    return null;
  }

  return {
    id: resume.id,
    originalName: resume.originalName,
    mimeType: resume.mimeType,
    sizeBytes: resume.sizeBytes,
    algorithm: resume.algorithm,
    keyVersion: resume.keyVersion,
    uploadedAt: resume.uploadedAt,
    accessUserIds: Array.isArray(resume.accessUserIds)
      ? resume.accessUserIds
      : [],
  };
}

function safeUserResponse(user) {
  if (!user) {
    return null;
  }

  const totpState = ensureUserTotpState(user);

  return {
    id: user.id,
    role: user.role,
    email: user.email,
    mobile: user.mobile,
    isEmailVerified: Boolean(user.isEmailVerified),
    isMobileVerified: Boolean(user.isMobileVerified),
    isSuspended: Boolean(user.isSuspended),
    totpEnabled: Boolean(totpState.isEnabled && totpState.secret),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    lastLoginAt: user.lastLoginAt || null,
    profile: user.profile || buildDefaultProfile(""),
    resume: safeResumeMetadata(user.resume),
  };
}

function getUserByIdentifier(db, identifier) {
  const rawIdentifier = String(identifier || "").trim();
  if (!rawIdentifier) {
    return null;
  }

  const normalizedEmail = normalizeEmail(rawIdentifier);
  const normalizedMobile = normalizeMobile(rawIdentifier);

  return (
    db.users.find((user) => user.id === rawIdentifier) ||
    db.users.find((user) => user.email === normalizedEmail) ||
    db.users.find((user) => user.mobile === normalizedMobile)
  );
}

function requireAuth(req, res, next) {
  const authorizationHeader = req.headers.authorization || "";
  if (!authorizationHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Missing Bearer token." });
    return;
  }

  try {
    const token = authorizationHeader.slice("Bearer ".length);
    const payload = verifyAuthToken(token);
    const db = readDb();
    const user = db.users.find((item) => item.id === payload.sub);
    if (!user) {
      res.status(401).json({ message: "User for this token no longer exists." });
      return;
    }

    if (user.isSuspended) {
      res.status(403).json({ message: "Account is suspended by admin." });
      return;
    }

    req.auth = {
      userId: user.id,
      role: user.role,
    };
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      res.status(403).json({ message: "Access denied." });
      return;
    }
    next();
  };
}

function migrateUsersToTotpIfNeeded() {
  const db = readDb();
  let changed = false;
  const now = new Date().toISOString();

  db.users.forEach((user) => {
    let userChanged = false;
    const previousState = JSON.stringify(user.totp || {});
    const totp = ensureUserTotpState(user);
    if (JSON.stringify(totp) !== previousState) {
      changed = true;
      userChanged = true;
    }

    if (user.otpSecrets || user.otpLastSentAt) {
      delete user.otpSecrets;
      delete user.otpLastSentAt;
      changed = true;
      userChanged = true;
    }

    if (userChanged) {
      user.updatedAt = now;
    }
  });

  if (changed) {
    writeDb(db);
    console.log("Migrated existing users to mandatory authenticator TOTP state.");
  }
}

function deleteUserRecord(db, userId) {
  const targetIndex = db.users.findIndex((user) => user.id === userId);
  if (targetIndex < 0) {
    return null;
  }

  const target = db.users[targetIndex];
  if (target.resume?.storageName) {
    const storedPath = path.join(RESUME_DIR, target.resume.storageName);
    if (fs.existsSync(storedPath)) {
      fs.unlinkSync(storedPath);
    }
  }

  db.users.splice(targetIndex, 1);
  return target;
}

function ensureDefaultAdminAccount() {
  const db = readDb();
  if (db.users.some((user) => user.role === "admin")) {
    return;
  }

  const adminEmail = normalizeEmail(
    process.env.DEFAULT_ADMIN_EMAIL || "admin@jobportal.local"
  );
  const adminMobile = normalizeMobile(
    process.env.DEFAULT_ADMIN_MOBILE || "9000000000"
  );
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || "Admin@12345!";
  const timestamp = new Date().toISOString();

  const adminUser = {
    id: uuidv4(),
    role: "admin",
    email: adminEmail,
    mobile: adminMobile,
    passwordHash: hashPassword(adminPassword),
    isEmailVerified: true,
    isMobileVerified: true,
    isSuspended: false,
    totp: {
      secret: "",
      pendingSecret: "",
      pendingIssuedAt: null,
      isEnabled: false,
      lastVerifiedAt: null,
    },
    profile: buildDefaultProfile("Platform Admin"),
    resume: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    lastLoginAt: null,
  };

  db.users.push(adminUser);
  appendAuditLog(db, {
    actorUserId: adminUser.id,
    action: "ADMIN_BOOTSTRAP_CREATED",
    targetUserId: adminUser.id,
    metadata: { email: adminEmail },
  });
  writeDb(db);

  // This log is intentionally explicit to make first-run access possible in local setup.
  console.log(
    `Default admin created: ${adminEmail} / ${adminPassword} (Authenticator setup required on first login)`
  );
}

app.get("/", (_, res) => {
  res.send("Secure Job Portal Backend Running");
});

app.get("/api/test", (_, res) => {
  res.json({ message: "API working" });
});

app.post("/api/auth/register", (req, res) => {
  const name = sanitizeText(req.body.name, 80);
  const email = normalizeEmail(req.body.email);
  const mobile = normalizeMobile(req.body.mobile);
  const password = String(req.body.password || "");
  const requestedRole = String(req.body.role || "user").toLowerCase();
  const role = ALLOWED_SELF_ROLES.has(requestedRole) ? requestedRole : "user";

  if (!name || !isValidEmail(email) || !isValidMobile(mobile)) {
    res.status(400).json({
      message: "Provide valid name, email, and mobile number (10-15 digits).",
    });
    return;
  }

  if (!PASSWORD_POLICY.test(password)) {
    res.status(400).json({
      message:
        "Password must be 8-64 chars with uppercase, lowercase, number, and symbol.",
    });
    return;
  }

  const db = readDb();
  const emailTaken = db.users.some((user) => user.email === email);
  const mobileTaken = db.users.some((user) => user.mobile === mobile);
  if (emailTaken || mobileTaken) {
    res.status(409).json({
      message: "An account with this email or mobile already exists.",
    });
    return;
  }

  const timestamp = new Date().toISOString();
  const user = {
    id: uuidv4(),
    role,
    email,
    mobile,
    passwordHash: hashPassword(password),
    isEmailVerified: true,
    isMobileVerified: true,
    isSuspended: false,
    totp: {
      secret: "",
      pendingSecret: "",
      pendingIssuedAt: null,
      isEnabled: false,
      lastVerifiedAt: null,
    },
    profile: buildDefaultProfile(name),
    resume: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    lastLoginAt: null,
  };

  db.users.push(user);
  appendAuditLog(db, {
    actorUserId: user.id,
    action: "USER_REGISTERED",
    targetUserId: user.id,
    metadata: { role: user.role, email: user.email },
  });
  writeDb(db);

  const responseBody = {
    message:
      "Registration successful. Sign in and complete authenticator app setup.",
    user: safeUserResponse(user),
  };

  res.status(201).json(responseBody);
});

app.post("/api/auth/request-otp", (_, res) => {
  res.status(410).json({
    message:
      "Email/SMS OTP is disabled. Use authenticator app (TOTP) for login and high-risk actions.",
  });
});

app.post("/api/auth/verify-otp", (_, res) => {
  res.status(410).json({
    message:
      "Email/SMS OTP is disabled. Use authenticator app (TOTP) for login and high-risk actions.",
  });
});

app.post("/api/auth/login", (req, res) => {
  const identifier = String(req.body.identifier || "").trim();
  const password = String(req.body.password || "");
  const otp = normalizeTotpCode(req.body.totp || req.body.otp);

  if (!identifier || !password) {
    res.status(400).json({
      message: "identifier and password are required.",
    });
    return;
  }

  const db = readDb();
  const user = getUserByIdentifier(db, identifier);

  if (!user || !verifyPassword(password, user.passwordHash)) {
    res.status(401).json({ message: "Invalid credentials." });
    return;
  }

  if (user.isSuspended) {
    res.status(403).json({ message: "Account is suspended by admin." });
    return;
  }

  const totpState = ensureUserTotpState(user);

  if (!totpState.isEnabled || !totpState.secret) {
    if (!totpState.pendingSecret) {
      totpState.pendingSecret = generateOtpSecret();
      totpState.pendingIssuedAt = new Date().toISOString();
      user.updatedAt = totpState.pendingIssuedAt;

      appendAuditLog(db, {
        actorUserId: user.id,
        action: "TOTP_SETUP_INITIATED",
        targetUserId: user.id,
        metadata: { flow: "login" },
      });
      writeDb(db);
    }

    if (!otp) {
      res.json({
        message:
          "Authenticator setup is required. Scan the QR code and enter the 6-digit code.",
        nextStep: "totp_setup",
        totpSetup: buildTotpSetupPayload(user, totpState.pendingSecret),
      });
      return;
    }

    if (!verifyTotp(totpState.pendingSecret, otp)) {
      res.status(401).json({
        message: "Invalid authenticator code. Complete setup and try again.",
      });
      return;
    }

    const now = new Date().toISOString();
    totpState.secret = totpState.pendingSecret;
    totpState.pendingSecret = "";
    totpState.pendingIssuedAt = null;
    totpState.isEnabled = true;
    totpState.lastVerifiedAt = now;
    user.lastLoginAt = now;
    user.updatedAt = now;

    appendAuditLog(db, {
      actorUserId: user.id,
      action: "TOTP_SETUP_COMPLETED",
      targetUserId: user.id,
      metadata: { flow: "login" },
    });
    appendAuditLog(db, {
      actorUserId: user.id,
      action: "USER_LOGIN_SUCCESS",
      targetUserId: user.id,
      metadata: { method: "totp_setup" },
    });
    writeDb(db);

    const token = signAuthToken({
      sub: user.id,
      role: user.role,
    });

    res.json({
      token,
      user: safeUserResponse(user),
      message: "Authenticator setup completed. Login successful.",
    });
    return;
  }

  if (!otp) {
    res.json({
      message: "Enter your authenticator app code to login.",
      nextStep: "totp_verify",
    });
    return;
  }

  if (!verifyUserTotp(user, otp)) {
    res.status(401).json({ message: "Invalid or expired authenticator code." });
    return;
  }

  const now = new Date().toISOString();
  totpState.lastVerifiedAt = now;
  user.lastLoginAt = now;
  user.updatedAt = now;

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "USER_LOGIN_SUCCESS",
    targetUserId: user.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  const token = signAuthToken({
    sub: user.id,
    role: user.role,
  });

  res.json({
    token,
    user: safeUserResponse(user),
  });
});

app.post("/api/auth/password-reset/request", (req, res) => {
  const identifier = String(req.body.identifier || "").trim();

  if (!identifier) {
    res.status(400).json({
      message: "identifier is required.",
    });
    return;
  }

  const db = readDb();
  const user = getUserByIdentifier(db, identifier);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (user.isSuspended) {
    res.status(403).json({ message: "Account is suspended." });
    return;
  }

  const totpState = ensureUserTotpState(user);
  if (!totpState.isEnabled || !totpState.secret) {
    res.status(400).json({
      message:
        "Authenticator app is not set up for this account. Login and complete setup first.",
    });
    return;
  }

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "PASSWORD_RESET_TOTP_CHALLENGE_REQUESTED",
    targetUserId: user.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  res.json({
    message:
      "Use your authenticator app code with new password to complete reset.",
  });
});

app.post("/api/auth/password-reset/confirm", (req, res) => {
  const identifier = String(req.body.identifier || "").trim();
  const otp = normalizeTotpCode(req.body.totp || req.body.otp);
  const newPassword = String(req.body.newPassword || "");

  if (!identifier || !otp || !newPassword) {
    res.status(400).json({
      message: "identifier, totp, and newPassword are required.",
    });
    return;
  }

  if (!PASSWORD_POLICY.test(newPassword)) {
    res.status(400).json({
      message:
        "Password must be 8-64 chars with uppercase, lowercase, number, and symbol.",
    });
    return;
  }

  const db = readDb();
  const user = getUserByIdentifier(db, identifier);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (user.isSuspended) {
    res.status(403).json({ message: "Account is suspended." });
    return;
  }

  if (!verifyUserTotp(user, otp)) {
    res.status(401).json({ message: "Invalid or expired authenticator code." });
    return;
  }

  const totpState = ensureUserTotpState(user);
  user.passwordHash = hashPassword(newPassword);
  user.updatedAt = new Date().toISOString();
  totpState.lastVerifiedAt = user.updatedAt;

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "PASSWORD_RESET_COMPLETED",
    targetUserId: user.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  res.json({ message: "Password reset successful. Please login again." });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (user.isSuspended) {
    res.status(403).json({ message: "Account is suspended by admin." });
    return;
  }

  res.json({ user: safeUserResponse(user) });
});

app.get("/api/profile/me", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({
    profile: user.profile || buildDefaultProfile(""),
    verification: {
      isEmailVerified: Boolean(user.isEmailVerified),
      isMobileVerified: Boolean(user.isMobileVerified),
    },
  });
});

app.put("/api/profile/me", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  const existingProfile = user.profile || buildDefaultProfile("");
  const updatedProfile = { ...existingProfile };

  if (typeof req.body.name === "string") {
    updatedProfile.name = sanitizeText(req.body.name, 80);
  }

  if (typeof req.body.headline === "string") {
    updatedProfile.headline = sanitizeText(req.body.headline, 120);
  }

  if (typeof req.body.location === "string") {
    updatedProfile.location = sanitizeText(req.body.location, 120);
  }

  if (typeof req.body.education === "string") {
    updatedProfile.education = sanitizeText(req.body.education, 400);
  }

  if (typeof req.body.experience === "string") {
    updatedProfile.experience = sanitizeText(req.body.experience, 600);
  }

  if (typeof req.body.profilePicture === "string") {
    updatedProfile.profilePicture = sanitizeText(req.body.profilePicture, 500);
  }

  if (typeof req.body.bio === "string") {
    updatedProfile.bio = sanitizeText(req.body.bio, 600);
  }

  if (req.body.skills !== undefined) {
    updatedProfile.skills = parseSkills(req.body.skills);
  }

  if (req.body.privacy && typeof req.body.privacy === "object") {
    const defaultPrivacy = defaultPrivacySettings();
    const nextPrivacy = { ...defaultPrivacy, ...existingProfile.privacy };

    Object.keys(defaultPrivacy).forEach((key) => {
      const value = String(req.body.privacy[key] || nextPrivacy[key]).toLowerCase();
      if (PROFILE_PRIVACY_OPTIONS.has(value)) {
        nextPrivacy[key] = value;
      }
    });

    updatedProfile.privacy = nextPrivacy;
  }

  user.profile = updatedProfile;
  user.updatedAt = new Date().toISOString();

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "PROFILE_UPDATED",
    targetUserId: user.id,
    metadata: {
      fields: Object.keys(req.body || {}),
    },
  });
  writeDb(db);

  res.json({
    message: "Profile updated.",
    profile: user.profile,
  });
});

app.post("/api/resume/upload", requireAuth, upload.single("resume"), (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (!req.file) {
    res.status(400).json({ message: "Attach a resume file in PDF or DOCX format." });
    return;
  }

  const encrypted = encryptBuffer(req.file.buffer);
  const storageName = `${user.id}-${Date.now()}-${uuidv4()}.enc`;
  const fullPath = path.join(RESUME_DIR, storageName);
  fs.writeFileSync(fullPath, encrypted.ciphertext);

  if (user.resume && user.resume.storageName) {
    const oldPath = path.join(RESUME_DIR, user.resume.storageName);
    if (fs.existsSync(oldPath)) {
      fs.unlinkSync(oldPath);
    }
  }

  user.resume = {
    id: uuidv4(),
    originalName: req.file.originalname,
    mimeType: req.file.mimetype,
    sizeBytes: req.file.size,
    storageName,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    algorithm: encrypted.algorithm,
    keyVersion: encrypted.keyVersion,
    uploadedAt: new Date().toISOString(),
    accessUserIds: Array.isArray(user.resume?.accessUserIds)
      ? user.resume.accessUserIds
      : [],
  };

  user.updatedAt = new Date().toISOString();

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "RESUME_UPLOADED_ENCRYPTED",
    targetUserId: user.id,
    metadata: {
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      sizeBytes: req.file.size,
    },
  });
  writeDb(db);

  res.status(201).json({
    message: "Resume uploaded and encrypted successfully.",
    resume: safeResumeMetadata(user.resume),
  });
});

app.get("/api/resume/me", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({ resume: safeResumeMetadata(user.resume) });
});

app.post("/api/resume/request-download-otp", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  const totpState = ensureUserTotpState(user);
  if (!totpState.isEnabled || !totpState.secret) {
    res.status(400).json({
      message:
        "Authenticator app is not set up for this account. Login and complete setup first.",
    });
    return;
  }

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "RESUME_DOWNLOAD_TOTP_CHALLENGE_REQUESTED",
    targetUserId: user.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  res.json({
    message:
      "Use your authenticator app code to continue with resume download.",
  });
});

app.post("/api/resume/grant-access", requireAuth, (req, res) => {
  const recruiterUserId = String(req.body.recruiterUserId || "").trim();
  if (!recruiterUserId) {
    res.status(400).json({ message: "recruiterUserId is required." });
    return;
  }

  const db = readDb();
  const owner = db.users.find((item) => item.id === req.auth.userId);
  if (!owner) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (!owner.resume) {
    res.status(400).json({ message: "Upload a resume first." });
    return;
  }

  const recruiter = db.users.find((item) => item.id === recruiterUserId);
  if (!recruiter || !["recruiter", "admin"].includes(recruiter.role)) {
    res.status(404).json({ message: "Recruiter/admin user not found." });
    return;
  }

  owner.resume.accessUserIds = Array.isArray(owner.resume.accessUserIds)
    ? owner.resume.accessUserIds
    : [];

  if (!owner.resume.accessUserIds.includes(recruiterUserId)) {
    owner.resume.accessUserIds.push(recruiterUserId);
  }

  owner.updatedAt = new Date().toISOString();

  appendAuditLog(db, {
    actorUserId: owner.id,
    action: "RESUME_ACCESS_GRANTED",
    targetUserId: recruiterUserId,
    metadata: { ownerId: owner.id },
  });
  writeDb(db);

  res.json({
    message: "Resume access granted.",
    resume: safeResumeMetadata(owner.resume),
  });
});

app.post("/api/resume/download", requireAuth, (req, res) => {
  const otp = normalizeTotpCode(req.body.totp || req.body.otp);
  const targetUserId = String(req.body.targetUserId || "").trim();

  if (!otp) {
    res.status(400).json({ message: "totp is required." });
    return;
  }

  const db = readDb();
  const requester = db.users.find((item) => item.id === req.auth.userId);
  if (!requester) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  const requestedOwnerId = targetUserId || requester.id;
  const owner = db.users.find((item) => item.id === requestedOwnerId);
  if (!owner || !owner.resume) {
    res.status(404).json({ message: "Resume not found for requested user." });
    return;
  }

  if (owner.id !== requester.id) {
    const isAdmin = requester.role === "admin";
    const isAuthorizedRecruiter =
      requester.role === "recruiter" &&
      Array.isArray(owner.resume.accessUserIds) &&
      owner.resume.accessUserIds.includes(requester.id);

    if (!isAdmin && !isAuthorizedRecruiter) {
      res.status(403).json({ message: "Not authorized to access this resume." });
      return;
    }
  }

  if (!verifyUserTotp(requester, otp)) {
    res.status(401).json({ message: "Invalid or expired authenticator code." });
    return;
  }

  const requesterTotp = ensureUserTotpState(requester);
  requesterTotp.lastVerifiedAt = new Date().toISOString();
  requester.updatedAt = requesterTotp.lastVerifiedAt;

  const encryptedPath = path.join(RESUME_DIR, owner.resume.storageName);
  if (!fs.existsSync(encryptedPath)) {
    res.status(404).json({ message: "Encrypted resume file not found." });
    return;
  }

  const encryptedPayload = fs.readFileSync(encryptedPath);
  const decrypted = decryptBuffer(
    encryptedPayload,
    owner.resume.iv,
    owner.resume.authTag
  );

  appendAuditLog(db, {
    actorUserId: requester.id,
    action: "RESUME_DOWNLOADED",
    targetUserId: owner.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  const safeFilename = String(owner.resume.originalName || "resume.bin").replace(
    /[^a-zA-Z0-9._-]/g,
    "_"
  );

  res.setHeader("Content-Type", owner.resume.mimeType || "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename=\"${safeFilename}\"`);
  res.send(decrypted);
});

app.post("/api/account/request-deletion-otp", requireAuth, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  const totpState = ensureUserTotpState(user);
  if (!totpState.isEnabled || !totpState.secret) {
    res.status(400).json({
      message:
        "Authenticator app is not set up for this account. Login and complete setup first.",
    });
    return;
  }

  appendAuditLog(db, {
    actorUserId: user.id,
    action: "ACCOUNT_DELETION_TOTP_CHALLENGE_REQUESTED",
    targetUserId: user.id,
    metadata: { method: "totp" },
  });
  writeDb(db);

  res.json({
    message: "Use your authenticator app code to confirm account deletion.",
  });
});

app.post("/api/account/delete", requireAuth, (req, res) => {
  const otp = normalizeTotpCode(req.body.totp || req.body.otp);

  if (!otp) {
    res.status(400).json({ message: "totp is required." });
    return;
  }

  const db = readDb();
  const user = db.users.find((item) => item.id === req.auth.userId);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  if (!verifyUserTotp(user, otp)) {
    res.status(401).json({ message: "Invalid or expired authenticator code." });
    return;
  }

  const deletedUser = deleteUserRecord(db, user.id);
  if (!deletedUser) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  appendAuditLog(db, {
    actorUserId: req.auth.userId,
    action: "ACCOUNT_SELF_DELETED",
    targetUserId: req.auth.userId,
    metadata: { method: "totp" },
  });
  writeDb(db);

  res.json({ message: "Account deleted successfully." });
});

app.get("/api/admin/overview", requireAuth, requireRole(["admin"]), (req, res) => {
  const db = readDb();
  const totalUsers = db.users.length;
  const verifiedUsers = db.users.filter((user) => {
    const totp = ensureUserTotpState(user);
    return Boolean(totp.isEnabled && totp.secret);
  }).length;
  const recruiterUsers = db.users.filter((user) => user.role === "recruiter").length;
  const suspendedUsers = db.users.filter((user) => user.isSuspended).length;
  const resumesUploaded = db.users.filter((user) => Boolean(user.resume)).length;

  res.json({
    totals: {
      totalUsers,
      verifiedUsers,
      recruiterUsers,
      suspendedUsers,
      resumesUploaded,
    },
    audit: {
      totalEntries: db.auditLogs.length,
      integrity: verifyAuditChain(db.auditLogs),
      recent: db.auditLogs.slice(-10).reverse(),
    },
  });
});

app.get("/api/admin/users", requireAuth, requireRole(["admin"]), (req, res) => {
  const db = readDb();
  const users = db.users.map((user) => safeUserResponse(user));
  res.json({ users });
});

app.patch(
  "/api/admin/users/:userId/suspension",
  requireAuth,
  requireRole(["admin"]),
  (req, res) => {
    const targetUserId = String(req.params.userId || "").trim();
    const isSuspended = req.body.isSuspended;
    const reason = sanitizeText(req.body.reason || "", 240);

    if (typeof isSuspended !== "boolean") {
      res.status(400).json({ message: "isSuspended boolean is required." });
      return;
    }

    if (targetUserId === req.auth.userId && isSuspended) {
      res.status(400).json({ message: "Admin cannot suspend their own account." });
      return;
    }

    const db = readDb();
    const target = db.users.find((user) => user.id === targetUserId);
    if (!target) {
      res.status(404).json({ message: "Target user not found." });
      return;
    }

    target.isSuspended = isSuspended;
    target.updatedAt = new Date().toISOString();

    appendAuditLog(db, {
      actorUserId: req.auth.userId,
      action: isSuspended ? "ADMIN_SUSPENDED_USER" : "ADMIN_REACTIVATED_USER",
      targetUserId,
      metadata: { reason },
    });
    writeDb(db);

    res.json({
      message: isSuspended ? "User suspended." : "User reactivated.",
      user: safeUserResponse(target),
    });
  }
);

app.delete(
  "/api/admin/users/:userId",
  requireAuth,
  requireRole(["admin"]),
  (req, res) => {
    const targetUserId = String(req.params.userId || "").trim();
    if (!targetUserId) {
      res.status(400).json({ message: "Target user id is required." });
      return;
    }

    if (targetUserId === req.auth.userId) {
      res.status(400).json({ message: "Admin cannot delete their own account." });
      return;
    }

    const db = readDb();
    const target = deleteUserRecord(db, targetUserId);
    if (!target) {
      res.status(404).json({ message: "Target user not found." });
      return;
    }

    appendAuditLog(db, {
      actorUserId: req.auth.userId,
      action: "ADMIN_DELETED_USER",
      targetUserId,
      metadata: { email: target.email, role: target.role },
    });
    writeDb(db);

    res.json({ message: "User deleted successfully." });
  }
);

app.get("/api/admin/audit-logs", requireAuth, requireRole(["admin"]), (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const db = readDb();
  res.json({
    integrity: verifyAuditChain(db.auditLogs),
    logs: db.auditLogs.slice(-limit).reverse(),
  });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      res.status(400).json({ message: "Resume file exceeds 5MB limit." });
      return;
    }

    res.status(400).json({ message: err.message });
    return;
  }

  if (err.message === "Only PDF and DOCX files are allowed.") {
    res.status(400).json({ message: err.message });
    return;
  }

  console.error(err);
  res.status(500).json({ message: "Internal server error." });
});

app.use((_, res) => {
  res.status(404).json({ message: "Route not found." });
});

ensureDirectories();
ensureDefaultAdminAccount();
migrateUsersToTotpIfNeeded();

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});

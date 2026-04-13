const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const { RESUME_DIR } = require("../config");
const { appendAuditLog } = require("../audit");
const User = require("../models/User");
const {
  hashPassword,
  verifyPassword,
  generateOtpSecret,
  verifyTotp,
  signAuthToken,
  encryptBuffer,
  decryptBuffer,
} = require("../security");
const {
  PROFILE_PRIVACY_OPTIONS,
  ALLOWED_SELF_ROLES,
  PASSWORD_POLICY,
  normalizeEmail,
  normalizeMobile,
  sanitizeText,
  sanitizeMultilineText,
  sanitizeUrl,
  parseSkills,
  normalizeTotpCode,
  isValidEmail,
  isValidMobile,
  buildDefaultProfile,
  ensureUserTotpState,
  buildTotpSetupPayload,
  verifyUserTotp,
  safeResumeMetadata,
  safeUserResponse,
  getUserByIdentifier,
  isRecruiterAuthorizedByApplication,
  deleteUserRecord,
  requireAuth,
} = require("../portal-helpers");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
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

function registerAuthProfileRoutes(app) {
  app.post("/api/auth/register", async (req, res) => {
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

    const emailTaken = await User.exists({ email });
    const mobileTaken = await User.exists({ mobile });
    if (emailTaken || mobileTaken) {
      res.status(409).json({
        message: "An account with this email or mobile already exists.",
      });
      return;
    }

    const timestamp = new Date().toISOString();
    const user = new User({
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
      messaging: {
        publicKey: null,
        encryptedPrivateKey: null,
        algorithm: "RSA-OAEP",
        updatedAt: null,
      },
      profile: buildDefaultProfile(name),
      resume: null,
      createdAt: timestamp,
      updatedAt: timestamp,
      lastLoginAt: null,
    });

    await user.save();
    await appendAuditLog({
      actorUserId: user.id,
      action: "USER_REGISTERED",
      targetUserId: user.id,
      metadata: { role: user.role, email: user.email },
    });

    res.status(201).json({
      message:
        "Registration successful. Sign in and complete authenticator app setup.",
      user: safeUserResponse(user),
    });
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

  app.post("/api/auth/login", async (req, res) => {
    const identifier = String(req.body.identifier || "").trim();
    const password = String(req.body.password || "");
    const otp = normalizeTotpCode(req.body.totp || req.body.otp);

    if (!identifier || !password) {
      res.status(400).json({ message: "identifier and password are required." });
      return;
    }

    const user = await getUserByIdentifier(identifier);
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
        const pendingSecret = generateOtpSecret();
        const pendingIssuedAt = new Date().toISOString();
        user.totp = {
          ...totpState,
          pendingSecret,
          pendingIssuedAt,
        };
        user.updatedAt = pendingIssuedAt;
        user.markModified("totp");
        await appendAuditLog({
          actorUserId: user.id,
          action: "TOTP_SETUP_INITIATED",
          targetUserId: user.id,
          metadata: { flow: "login" },
        });
        await user.save();
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
      user.totp = {
        ...totpState,
        secret: totpState.pendingSecret,
        pendingSecret: "",
        pendingIssuedAt: null,
        isEnabled: true,
        lastVerifiedAt: now,
      };
      user.lastLoginAt = now;
      user.updatedAt = now;
      await appendAuditLog({
        actorUserId: user.id,
        action: "TOTP_SETUP_COMPLETED",
        targetUserId: user.id,
        metadata: { flow: "login" },
      });
      await appendAuditLog({
        actorUserId: user.id,
        action: "USER_LOGIN_SUCCESS",
        targetUserId: user.id,
        metadata: { method: "totp_setup" },
      });
      user.markModified("totp");
      await user.save();

      res.json({
        token: signAuthToken({ sub: user.id, role: user.role }),
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
    user.totp = {
      ...totpState,
      lastVerifiedAt: now,
    };
    user.lastLoginAt = now;
    user.updatedAt = now;
      metadata: { method: "totp" },
    });
    user.markModified("totp");
    await user.save();

    res.json({
      token: signAuthToken({ sub: user.id, role: user.role }),
      user: safeUserResponse(user),
    });
  });

  app.post("/api/auth/password-reset/request", async (req, res) => {
    const identifier = String(req.body.identifier || "").trim();
    if (!identifier) {
      res.status(400).json({ message: "identifier is required." });
      return;
    }

    const user = await getUserByIdentifier(identifier);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    if (user.isSuspended) {
      res.status(403).json({ message: "Account is suspended." });
      return;
    }

    if (!ensureUserTotpState(user).isEnabled || !user.totp.secret) {
      res.status(400).json({
        message:
          "Authenticator app is not set up for this account. Login and complete setup first.",
      });
      return;
    }

    await appendAuditLog({
      actorUserId: user.id,
      action: "PASSWORD_RESET_TOTP_CHALLENGE_REQUESTED",
      targetUserId: user.id,
      metadata: { method: "totp" },
    });

    res.json({
      message:
        "Use your authenticator app code with new password to complete reset.",
    });
  });

  app.post("/api/auth/password-reset/confirm", async (req, res) => {
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

    const user = await getUserByIdentifier(identifier);
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

    user.passwordHash = hashPassword(newPassword);
    user.updatedAt = new Date().toISOString();
    const totpState = ensureUserTotpState(user);
    user.totp = {
      ...totpState,
      lastVerifiedAt: user.updatedAt,
    };
      metadata: { method: "totp" },
    });
    user.markModified("totp");
    await user.save();

    res.json({ message: "Password reset successful. Please login again." });
  });

  app.get("/api/auth/me", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json({ user: safeUserResponse(user) });
  });

  app.get("/api/profile/me", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
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

  app.put("/api/profile/me", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    const existingProfile = user.profile || buildDefaultProfile("");
    const updatedProfile = { ...existingProfile };
    if (typeof req.body.name === "string") updatedProfile.name = sanitizeText(req.body.name, 80);
    if (typeof req.body.headline === "string") updatedProfile.headline = sanitizeText(req.body.headline, 120);
    if (typeof req.body.location === "string") updatedProfile.location = sanitizeText(req.body.location, 120);
    if (typeof req.body.education === "string") updatedProfile.education = sanitizeMultilineText(req.body.education, 400);
    if (typeof req.body.experience === "string") updatedProfile.experience = sanitizeMultilineText(req.body.experience, 600);
    if (typeof req.body.profilePicture === "string") updatedProfile.profilePicture = sanitizeUrl(req.body.profilePicture);
    if (typeof req.body.bio === "string") updatedProfile.bio = sanitizeMultilineText(req.body.bio, 600);
    if (req.body.skills !== undefined) updatedProfile.skills = parseSkills(req.body.skills);

    if (req.body.privacy && typeof req.body.privacy === "object") {
      const nextPrivacy = { ...existingProfile.privacy };
      Object.keys(nextPrivacy).forEach((key) => {
        const value = String(req.body.privacy[key] || nextPrivacy[key]).toLowerCase();
        if (PROFILE_PRIVACY_OPTIONS.has(value)) {
          nextPrivacy[key] = value;
        }
      });
      updatedProfile.privacy = nextPrivacy;
    }

    user.profile = updatedProfile;
    user.updatedAt = new Date().toISOString();
    user.markModified("profile");
    await appendAuditLog({
      actorUserId: user.id,
      action: "PROFILE_UPDATED",
      targetUserId: user.id,
      metadata: { fields: Object.keys(req.body || {}) },
    });
    await user.save();

    res.json({ message: "Profile updated.", profile: user.profile });
  });

  app.post("/api/resume/upload", requireAuth, upload.single("resume"), async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
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
    fs.writeFileSync(path.join(RESUME_DIR, storageName), encrypted.ciphertext);

    if (user.resume?.storageName) {
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
    await appendAuditLog({
      actorUserId: user.id,
      action: "RESUME_UPLOADED_ENCRYPTED",
      targetUserId: user.id,
      metadata: {
        fileName: req.file.originalname,
        mimeType: req.file.mimetype,
        sizeBytes: req.file.size,
      },
    });
    user.markModified("resume");
    await user.save();

    res.status(201).json({
      message: "Resume uploaded and encrypted successfully.",
      resume: safeResumeMetadata(user.resume),
    });
  });

  app.get("/api/resume/me", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }
    res.json({ resume: safeResumeMetadata(user.resume) });
  });

  app.post("/api/resume/request-download-otp", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }
    if (!ensureUserTotpState(user).isEnabled || !user.totp.secret) {
      res.status(400).json({
        message:
          "Authenticator app is not set up for this account. Login and complete setup first.",
      });
      return;
    }
    await appendAuditLog({
      actorUserId: user.id,
      action: "RESUME_DOWNLOAD_TOTP_CHALLENGE_REQUESTED",
      targetUserId: user.id,
      metadata: { method: "totp" },
    });
    res.json({
      message:
        "Use your authenticator app code to continue with resume download.",
    });
  });

  app.post("/api/resume/grant-access", requireAuth, async (req, res) => {
    const recruiterUserId = String(req.body.recruiterUserId || "").trim();
    if (!recruiterUserId) {
      res.status(400).json({ message: "recruiterUserId is required." });
      return;
    }

    const owner = await User.findOne({ id: req.auth.userId });
    const recruiter = await User.findOne({ id: recruiterUserId });
    if (!owner || !owner.resume) {
      res.status(400).json({ message: "Upload a resume first." });
      return;
    }
    if (!recruiter || !["recruiter", "admin"].includes(recruiter.role)) {
      res.status(404).json({ message: "Recruiter/admin user not found." });
      return;
    }

    owner.resume.accessUserIds = Array.isArray(owner.resume.accessUserIds)
      ? owner.resume.accessUserIds
      : [];
    if (!owner.resume.accessUserIds.includes(recruiterUserId)) {
      owner.resume.accessUserIds.push(recruiterUserId);
      owner.markModified("resume");
    }
    owner.updatedAt = new Date().toISOString();
    await appendAuditLog({
      actorUserId: owner.id,
      action: "RESUME_ACCESS_GRANTED",
      targetUserId: recruiterUserId,
      metadata: { ownerId: owner.id },
    });
    await owner.save();

    res.json({
      message: "Resume access granted.",
      resume: safeResumeMetadata(owner.resume),
    });
  });

  app.post("/api/resume/download", requireAuth, async (req, res) => {
    const otp = normalizeTotpCode(req.body.totp || req.body.otp);
    const targetUserId = String(req.body.targetUserId || "").trim();
    if (!otp) {
      res.status(400).json({ message: "totp is required." });
      return;
    }

    const requester = await User.findOne({ id: req.auth.userId });
    const owner = await User.findOne({
      id: (targetUserId || req.auth.userId)
    });
    if (!requester) {
      res.status(404).json({ message: "User not found." });
      return;
    }
    if (!owner || !owner.resume) {
      res.status(404).json({ message: "Resume not found for requested user." });
      return;
    }

    if (owner.id !== requester.id) {
      const isAuthorizedRecruiter =
        ((requester.role === "recruiter" &&
          Array.isArray(owner.resume.accessUserIds) &&
          owner.resume.accessUserIds.includes(requester.id)) ||
          await isRecruiterAuthorizedByApplication(requester.id, owner.id)) &&
        requester.role !== "admin";
      if (requester.role !== "admin" && !isAuthorizedRecruiter) {
        res.status(403).json({ message: "Not authorized to access this resume." });
        return;
      }
    }

    if (!verifyUserTotp(requester, otp)) {
      res.status(401).json({ message: "Invalid or expired authenticator code." });
      return;
    }

    ensureUserTotpState(requester).lastVerifiedAt = new Date().toISOString();
    requester.updatedAt = requester.totp.lastVerifiedAt;
    const encryptedPath = path.join(RESUME_DIR, owner.resume.storageName);
    if (!fs.existsSync(encryptedPath)) {
      res.status(404).json({ message: "Encrypted resume file not found." });
      return;
    }

    const decrypted = decryptBuffer(
      fs.readFileSync(encryptedPath),
      owner.resume.iv,
      owner.resume.authTag
    );
    await appendAuditLog({
      actorUserId: requester.id,
      action: "RESUME_DOWNLOADED",
      targetUserId: owner.id,
      metadata: { method: "totp" },
    });
    requester.markModified("totp");
    await requester.save();

    const safeFilename = String(owner.resume.originalName || "resume.bin").replace(
      /[^a-zA-Z0-9._-]/g,
      "_"
    );
    res.setHeader("Content-Type", owner.resume.mimeType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename=\"${safeFilename}\"`);
    res.send(decrypted);
  });

  app.post("/api/account/request-deletion-otp", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }
    if (!ensureUserTotpState(user).isEnabled || !user.totp.secret) {
      res.status(400).json({
        message:
          "Authenticator app is not set up for this account. Login and complete setup first.",
      });
      return;
    }
    await appendAuditLog({
      actorUserId: user.id,
      action: "ACCOUNT_DELETION_TOTP_CHALLENGE_REQUESTED",
      targetUserId: user.id,
      metadata: { method: "totp" },
    });
    res.json({
      message: "Use your authenticator app code to confirm account deletion.",
    });
  });

  app.post("/api/account/delete", requireAuth, async (req, res) => {
    const otp = normalizeTotpCode(req.body.totp || req.body.otp);
    if (!otp) {
      res.status(400).json({ message: "totp is required." });
      return;
    }

    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }
    if (!verifyUserTotp(user, otp)) {
      res.status(401).json({ message: "Invalid or expired authenticator code." });
      return;
    }

    const deletedUser = await deleteUserRecord(user.id);
    if (!deletedUser) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    await appendAuditLog({
      actorUserId: req.auth.userId,
      action: "ACCOUNT_SELF_DELETED",
      targetUserId: req.auth.userId,
      metadata: { method: "totp" },
    });
    res.json({ message: "Account deleted successfully." });
  });
}

module.exports = {
  registerAuthProfileRoutes,
};

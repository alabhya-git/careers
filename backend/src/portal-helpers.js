const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const { RESUME_DIR, OTP_STEP_SECONDS, TOTP_ISSUER } = require("./config");
const { appendAuditLog } = require("./audit");
const User = require("./models/User");
const Company = require("./models/Company");
const Job = require("./models/Job");
const Application = require("./models/Application");
const Conversation = require("./models/Conversation");
const AuditLog = require("./models/AuditLog");
const { hashPassword, verifyTotp, verifyAuthToken } = require("./security");

const PROFILE_PRIVACY_OPTIONS = new Set(["public", "connections", "private"]);
const ALLOWED_SELF_ROLES = new Set(["user", "recruiter"]);
const PASSWORD_POLICY =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,64}$/;
const TOTP_SETUP_QR_SIZE = 240;
const JOB_WORKPLACE_TYPES = new Set(["remote", "on-site", "hybrid"]);
const JOB_EMPLOYMENT_TYPES = new Set([
  "full-time",
  "part-time",
  "contract",
  "internship",
]);
const JOB_STATUSES = new Set(["open", "closed"]);
const APPLICATION_STATUSES = new Set([
  "Applied",
  "Reviewed",
  "Interviewed",
  "Rejected",
  "Offer",
]);
const CONVERSATION_TYPES = new Set(["direct", "group"]);
const MAX_GROUP_MEMBERS = 6;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeMobile(mobile) {
  return String(mobile || "").replace(/[^\d]/g, "");
}

function sanitizeText(value, maxLength = 255) {
  return String(value || "").replace(/\0/g, "").trim().slice(0, maxLength);
}

function sanitizeMultilineText(value, maxLength = 1200) {
  return String(value || "").replace(/\0/g, "").trim().slice(0, maxLength);
}

function sanitizeUrl(value) {
  const normalized = sanitizeText(value, 300);
  if (!normalized) {
    return "";
  }

  try {
    const parsed = new URL(normalized);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.toString() : "";
  } catch (error) {
    return "";
  }
}

function parseDateInput(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function parseOptionalCurrency(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.round(parsed) : null;
}

function parseIdList(input) {
  if (!Array.isArray(input)) {
    return [];
  }

  return Array.from(
    new Set(input.map((item) => sanitizeText(item, 80)).filter(Boolean))
  );
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

function normalizeTotpCode(value) {
  return String(value || "").replace(/\s+/g, "");
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidMobile(mobile) {
  return /^\d{10,15}$/.test(mobile);
}

function slugify(value) {
  return (
    sanitizeText(value, 120)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "company"
  );
}

function isDeadlinePassed(deadline) {
  if (!deadline) {
    return false;
  }

  const parsed = new Date(deadline);
  return Number.isFinite(parsed.getTime()) && parsed.getTime() < Date.now();
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

function defaultMessagingState() {
  return {
    publicKey: null,
    encryptedPrivateKey: null,
    algorithm: "RSA-OAEP",
    updatedAt: null,
  };
}

function ensureMessagingState(user) {
  if (!isPlainObject(user.messaging)) {
    user.messaging = defaultMessagingState();
  }

  if (!isPlainObject(user.messaging.publicKey)) {
    user.messaging.publicKey = null;
  }

  if (!isPlainObject(user.messaging.encryptedPrivateKey)) {
    user.messaging.encryptedPrivateKey = null;
  }

  if (typeof user.messaging.algorithm !== "string") {
    user.messaging.algorithm = "RSA-OAEP";
  }

  if (
    user.messaging.updatedAt !== null &&
    typeof user.messaging.updatedAt !== "string"
  ) {
    user.messaging.updatedAt = null;
  }

  return user.messaging;
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

  if (typeof user.markModified === "function") {
    user.markModified("totp");
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
  return Boolean(
    totpState.isEnabled &&
      totpState.secret &&
      verifyTotp(totpState.secret, normalizeTotpCode(code))
  );
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

function safeMessagingStatus(user) {
  const messaging = ensureMessagingState(user);
  return {
    isConfigured: Boolean(messaging.publicKey && messaging.encryptedPrivateKey),
    algorithm: messaging.algorithm,
    updatedAt: messaging.updatedAt,
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
    messaging: safeMessagingStatus(user),
  };
}

function directoryUserPreview(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    role: user.role,
    email: user.email,
    profile: {
      name: user.profile?.name || user.email,
      headline: user.profile?.headline || "",
      location: user.profile?.location || "",
      skills: Array.isArray(user.profile?.skills) ? user.profile.skills : [],
      profilePicture: user.profile?.profilePicture || "",
    },
    messaging: {
      ...safeMessagingStatus(user),
      publicKey: ensureMessagingState(user).publicKey,
    },
  };
}

async function getUserByIdentifier(identifier) {
  const rawIdentifier = String(identifier || "").trim();
  if (!rawIdentifier) {
    return null;
  }

  const normalizedEmail = normalizeEmail(rawIdentifier);
  const normalizedMobile = normalizeMobile(rawIdentifier);

  return await User.findOne({
    $or: [
      { id: rawIdentifier },
      { email: normalizedEmail },
      { mobile: normalizedMobile },
    ],
  });
}

async function getManagedCompanyIds(user) {
  if (!user) {
    return [];
  }

  let companies;
  if (user.role === "admin") {
    companies = await Company.find({}, "id");
  } else {
    companies = await Company.find({
      $or: [
        { createdByUserId: user.id },
        { adminUserIds: user.id },
      ],
    }, "id");
  }

  return companies.map((company) => company.id);
}

function canManageCompany(user, company) {
  if (!user || !company) {
    return false;
  }

  if (user.role === "admin") {
    return true;
  }

  const adminUserIds = Array.isArray(company.adminUserIds)
    ? company.adminUserIds
    : [];

  return company.createdByUserId === user.id || adminUserIds.includes(user.id);
}

async function getCompanyById(companyId) {
  return await Company.findOne({ id: companyId });
}

async function getJobById(jobId) {
  return await Job.findOne({ id: jobId });
}

async function getApplicationById(applicationId) {
  return await Application.findOne({ id: applicationId });
}

async function createUniqueCompanySlug(name, excludeCompanyId = null) {
  const baseSlug = slugify(name);
  let candidate = baseSlug;
  let suffix = 2;

  while (
    await Company.exists({
      slug: candidate,
      id: { $ne: excludeCompanyId },
    })
  ) {
    candidate = `${baseSlug}-${suffix}`;
    suffix += 1;
  }

  return candidate;
}

async function requireAuth(req, res, next) {
  const authorizationHeader = req.headers.authorization || "";
  if (!authorizationHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Missing Bearer token." });
    return;
  }

  try {
    const payload = verifyAuthToken(
      authorizationHeader.slice("Bearer ".length)
    );
    const user = await User.findOne({ id: payload.sub });
    if (!user) {
      res.status(401).json({ message: "User for this token no longer exists." });
      return;
    }

    if (user.isSuspended) {
      res.status(403).json({ message: "Account is suspended by admin." });
      return;
    }

    req.auth = { userId: user.id, role: user.role };
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

async function serializeCompany(company, viewer = null) {
  const jobs = await Job.find({ companyId: company.id });
  const openJobs = jobs.filter(
    (job) => job.status === "open" && !isDeadlinePassed(job.applicationDeadline)
  );

  const adminUsers = await User.find({ id: { $in: company.adminUserIds || [] } });

  return {
    id: company.id,
    slug: company.slug,
    name: company.name,
    description: company.description,
    location: company.location,
    website: company.website,
    createdByUserId: company.createdByUserId || null,
    createdAt: company.createdAt,
    updatedAt: company.updatedAt,
    admins: adminUsers.map((user) => directoryUserPreview(user)).filter(Boolean),
    counts: {
      totalJobs: jobs.length,
      openJobs: openJobs.length,
    },
    canManage: canManageCompany(viewer, company),
  };
}

async function serializeJob(job, viewer = null) {
  const company = await getCompanyById(job.companyId);
  const applicantCount = await Application.countDocuments({ jobId: job.id });
  const canManage = canManageCompany(viewer, company);

  return {
    id: job.id,
    companyId: job.companyId,
    title: job.title,
    description: job.description,
    requiredSkills: Array.isArray(job.requiredSkills) ? job.requiredSkills : [],
    location: job.location,
    workplaceType: job.workplaceType,
    employmentType: job.employmentType,
    salaryMin: job.salaryMin ?? null,
    salaryMax: job.salaryMax ?? null,
    applicationDeadline: job.applicationDeadline || null,
    status: job.status,
    createdByUserId: job.createdByUserId,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    isExpired: isDeadlinePassed(job.applicationDeadline),
    company: company
      ? {
          id: company.id,
          slug: company.slug,
          name: company.name,
          location: company.location,
          website: company.website,
        }
      : null,
    applicantCount: canManage ? applicantCount : undefined,
    canManage,
  };
}

async function serializeApplication(application, viewer = null) {
  const applicant = await User.findOne({ id: application.applicantUserId });
  const job = await getJobById(application.jobId);
  const company = job ? await getCompanyById(job.companyId) : null;
  const viewerIsApplicant = viewer && viewer.id === application.applicantUserId;
  const viewerCanManage = canManageCompany(viewer, company);

  return {
    id: application.id,
    jobId: application.jobId,
    companyId: application.companyId,
    applicantUserId: application.applicantUserId,
    status: application.status,
    isShortlisted: Boolean(application.isShortlisted),
    coverNote: application.coverNote,
    createdAt: application.createdAt,
    updatedAt: application.updatedAt,
    statusHistory: Array.isArray(application.statusHistory)
      ? application.statusHistory
      : [],
    recruiterNotes:
      viewerCanManage || viewer?.role === "admin"
        ? Array.isArray(application.recruiterNotes)
          ? application.recruiterNotes
          : []
        : [],
    applicant:
      viewerCanManage || viewer?.role === "admin" || viewerIsApplicant
        ? directoryUserPreview(applicant)
        : null,
    applicantResume:
      viewerCanManage || viewer?.role === "admin" || viewerIsApplicant
        ? safeResumeMetadata(applicant?.resume)
        : null,
    company: company
      ? {
          id: company.id,
          name: company.name,
          slug: company.slug,
        }
      : null,
    job: job
      ? {
          id: job.id,
          title: job.title,
          location: job.location,
          workplaceType: job.workplaceType,
          employmentType: job.employmentType,
          applicationDeadline: job.applicationDeadline,
          status: job.status,
        }
      : null,
  };
}

async function serializeConversation(conversation, viewerUserId) {
  const latestMessage =
    Array.isArray(conversation.messages) && conversation.messages.length
      ? conversation.messages[conversation.messages.length - 1]
      : null;
  const participantKey =
    Array.isArray(conversation.participantKeys) &&
    conversation.participantKeys.find((item) => item.userId === viewerUserId);

  const members = await User.find({ id: { $in: conversation.memberUserIds || [] } });

  return {
    id: conversation.id,
    type: conversation.type,
    title: conversation.title || "",
    createdByUserId: conversation.createdByUserId,
    createdAt: conversation.createdAt,
    updatedAt: conversation.updatedAt,
    lastMessageAt: conversation.lastMessageAt || null,
    messagesCount: Array.isArray(conversation.messages)
      ? conversation.messages.length
      : 0,
    members: members.map((user) => directoryUserPreview(user)).filter(Boolean),
    participantKey: participantKey || null,
    latestMessage: latestMessage
      ? {
          id: latestMessage.id,
          senderUserId: latestMessage.senderUserId,
          sentAt: latestMessage.sentAt,
          algorithm: latestMessage.algorithm,
        }
      : null,
  };
}

async function serializeEncryptedMessage(message) {
  const sender = await User.findOne({ id: message.senderUserId });
  return {
    id: message.id,
    senderUserId: message.senderUserId,
    sender: directoryUserPreview(sender),
    ciphertext: message.ciphertext,
    iv: message.iv,
    algorithm: message.algorithm,
    sentAt: message.sentAt,
  };
}

async function findConversationById(conversationId) {
  return await Conversation.findOne({ id: conversationId });
}

async function getMessagingDirectory(user) {
  const allowedUserIds = new Set();
  const db = {
    users: await User.find({}),
    applications: await Application.find({}),
    companies: await Company.find({}),
    conversations: await Conversation.find({}),
  };

  if (user.role === "admin") {
    db.users.forEach((candidate) => {
      if (candidate.id !== user.id) {
        allowedUserIds.add(candidate.id);
      }
    });
  }

  if (user.role === "recruiter") {
    const managedCompanyIds = new Set(await getManagedCompanyIds(user));
    db.applications.forEach((application) => {
      if (managedCompanyIds.has(application.companyId)) {
        allowedUserIds.add(application.applicantUserId);
      }
    });
    db.companies.forEach((company) => {
      if (!managedCompanyIds.has(company.id)) {
        return;
      }
      (Array.isArray(company.adminUserIds) ? company.adminUserIds : []).forEach(
        (adminUserId) => {
          if (adminUserId !== user.id) {
            allowedUserIds.add(adminUserId);
          }
        }
      );
    });
  }

  if (user.role === "user") {
    const companyIds = new Set(
      db.applications
        .filter((application) => application.applicantUserId === user.id)
        .map((application) => application.companyId)
    );
    db.companies.forEach((company) => {
      if (!companyIds.has(company.id)) {
        return;
      }
      (Array.isArray(company.adminUserIds) ? company.adminUserIds : []).forEach(
        (adminUserId) => {
          if (adminUserId !== user.id) {
            allowedUserIds.add(adminUserId);
          }
        }
      );
    });
  }

  db.conversations.forEach((conversation) => {
    if (!Array.isArray(conversation.memberUserIds)) {
      return;
    }
    if (!conversation.memberUserIds.includes(user.id)) {
      return;
    }
    conversation.memberUserIds.forEach((memberUserId) => {
      if (memberUserId !== user.id) {
        allowedUserIds.add(memberUserId);
      }
    });
  });

  return Array.from(allowedUserIds)
    .map((candidateId) =>
      directoryUserPreview(db.users.find((candidate) => candidate.id === candidateId))
    )
    .filter(Boolean)
    .sort((left, right) => {
      const leftName = left.profile?.name || left.email;
      const rightName = right.profile?.name || right.email;
      return leftName.localeCompare(rightName);
    });
}

async function isRecruiterAuthorizedByApplication(recruiterUserId, ownerUserId) {
  const recruiter = await User.findOne({ id: recruiterUserId });
  if (!recruiter || recruiter.role !== "recruiter") {
    return false;
  }

  const managedCompanyIds = new Set(await getManagedCompanyIds(recruiter));
  return await Application.exists({
    applicantUserId: ownerUserId,
    companyId: { $in: Array.from(managedCompanyIds) },
  });
}

async function migrateUsersAndCollectionsIfNeeded() {
  const users = await User.find({});
  const companies = await Company.find({});
  const jobs = await Job.find({});
  const applications = await Application.find({});
  const conversations = await Conversation.find({});

  const now = new Date().toISOString();

  for (const user of users) {
    let userChanged = false;
    const previousTotp = JSON.stringify(user.totp || {});
    const previousMessaging = JSON.stringify(user.messaging || {});
    if (JSON.stringify(ensureUserTotpState(user)) !== previousTotp) {
      userChanged = true;
    }
    if (JSON.stringify(ensureMessagingState(user)) !== previousMessaging) {
      userChanged = true;
    }
    if (user.otpSecrets || user.otpLastSentAt) {
      user.set("otpSecrets", undefined);
      user.set("otpLastSentAt", undefined);
      userChanged = true;
    }
    if (userChanged) {
      user.updatedAt = user.updatedAt || now;
      user.markModified("totp");
      user.markModified("messaging");
      await user.save();
    }
  }

  for (const company of companies) {
    let companyChanged = false;
    if (!Array.isArray(company.adminUserIds)) {
      company.adminUserIds = company.createdByUserId ? [company.createdByUserId] : [];
      companyChanged = true;
    }
    company.adminUserIds = Array.from(new Set(company.adminUserIds.filter(Boolean)));
    if (!company.slug) {
      company.slug = await createUniqueCompanySlug(company.name || "company", company.id);
      companyChanged = true;
    }
    if (companyChanged) {
      await company.save();
    }
  }

  for (const job of jobs) {
    let jobChanged = false;
    if (!Array.isArray(job.requiredSkills)) {
      job.requiredSkills = [];
      jobChanged = true;
    }
    if (!JOB_STATUSES.has(job.status)) {
      job.status = "open";
      jobChanged = true;
    }
    if (jobChanged) {
      await job.save();
    }
  }

  for (const application of applications) {
    let appChanged = false;
    if (!APPLICATION_STATUSES.has(application.status)) {
      application.status = "Applied";
      appChanged = true;
    }
    if (!Array.isArray(application.recruiterNotes)) {
      application.recruiterNotes = [];
      appChanged = true;
    }
    if (!Array.isArray(application.statusHistory)) {
      application.statusHistory = [];
      appChanged = true;
    }
    if (appChanged) {
      await application.save();
    }
  }

  for (const conversation of conversations) {
    let convChanged = false;
    if (!Array.isArray(conversation.memberUserIds)) {
      conversation.memberUserIds = [];
      convChanged = true;
    }
    if (!Array.isArray(conversation.participantKeys)) {
      conversation.participantKeys = [];
      convChanged = true;
    }
    if (!Array.isArray(conversation.messages)) {
      conversation.messages = [];
      convChanged = true;
    }
    if (!CONVERSATION_TYPES.has(conversation.type)) {
      conversation.type =
        conversation.memberUserIds.length > 2 ? "group" : "direct";
      convChanged = true;
    }
    if (convChanged) {
      await conversation.save();
    }
  }
}

async function deleteUserRecord(userId) {
  const target = await User.findOne({ id: userId });
  if (!target) {
    return null;
  }

  if (target.resume?.storageName) {
    const storedPath = path.join(RESUME_DIR, target.resume.storageName);
    if (fs.existsSync(storedPath)) {
      fs.unlinkSync(storedPath);
    }
  }

  await User.deleteOne({ id: userId });

  await User.updateMany(
    { "resume.accessUserIds": userId },
    { $pull: { "resume.accessUserIds": userId } }
  );

  await Company.updateMany(
    { adminUserIds: userId },
    { $pull: { adminUserIds: userId } }
  );
  await Company.updateMany(
    { createdByUserId: userId },
    { $set: { createdByUserId: null } }
  );

  await Application.deleteMany({ applicantUserId: userId });

  const convs = await Conversation.find({ memberUserIds: userId });
  for (const conv of convs) {
    const nextMembers = conv.memberUserIds.filter((id) => id !== userId);
    if (nextMembers.length < 2) {
      await Conversation.deleteOne({ id: conv.id });
    } else {
      conv.memberUserIds = nextMembers;
      conv.participantKeys = Array.isArray(conv.participantKeys)
        ? conv.participantKeys.filter((item) => item.userId !== userId)
        : [];
      await conv.save();
    }
  }

  return target;
}

async function ensureDefaultAdminAccount() {
  const adminExists = await User.exists({ role: "admin" });
  if (adminExists) {
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

  const adminUser = new User({
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
    messaging: defaultMessagingState(),
    profile: buildDefaultProfile("Platform Admin"),
    resume: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    lastLoginAt: null,
  });

  await adminUser.save();
  await appendAuditLog({
    actorUserId: adminUser.id,
    action: "ADMIN_BOOTSTRAP_CREATED",
    targetUserId: adminUser.id,
    metadata: { email: adminEmail },
  });
}

module.exports = {
  PROFILE_PRIVACY_OPTIONS,
  ALLOWED_SELF_ROLES,
  PASSWORD_POLICY,
  JOB_WORKPLACE_TYPES,
  JOB_EMPLOYMENT_TYPES,
  JOB_STATUSES,
  APPLICATION_STATUSES,
  CONVERSATION_TYPES,
  MAX_GROUP_MEMBERS,
  normalizeEmail,
  normalizeMobile,
  sanitizeText,
  sanitizeMultilineText,
  sanitizeUrl,
  parseDateInput,
  parseOptionalCurrency,
  parseIdList,
  parseSkills,
  normalizeTotpCode,
  isPlainObject,
  isValidEmail,
  isValidMobile,
  isDeadlinePassed,
  defaultPrivacySettings,
  buildDefaultProfile,
  defaultMessagingState,
  ensureMessagingState,
  ensureUserTotpState,
  buildTotpSetupPayload,
  verifyUserTotp,
  safeResumeMetadata,
  safeMessagingStatus,
  safeUserResponse,
  directoryUserPreview,
  getUserByIdentifier,
  getManagedCompanyIds,
  canManageCompany,
  getCompanyById,
  getJobById,
  getApplicationById,
  createUniqueCompanySlug,
  serializeCompany,
  serializeJob,
  serializeApplication,
  serializeConversation,
  serializeEncryptedMessage,
  findConversationById,
  getMessagingDirectory,
  isRecruiterAuthorizedByApplication,
  migrateUsersAndCollectionsIfNeeded,
  deleteUserRecord,
  ensureDefaultAdminAccount,
  requireAuth,
  requireRole,
};

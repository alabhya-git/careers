const { appendAuditLog, verifyAuditChain } = require("../audit");
const User = require("../models/User");
const Company = require("../models/Company");
const Job = require("../models/Job");
const Application = require("../models/Application");
const Conversation = require("../models/Conversation");
const AuditLog = require("../models/AuditLog");
const {
  sanitizeText,
  ensureUserTotpState,
  safeMessagingStatus,
  safeUserResponse,
  deleteUserRecord,
  requireAuth,
  requireRole,
} = require("../portal-helpers");

function registerAdminRoutes(app) {
  app.get("/api/admin/overview", requireAuth, requireRole(["admin"]), async (req, res) => {
    const users = await User.find({});
    const jobs = await Job.find({});
    const companies = await Company.find({});
    const applications = await Application.find({});
    const conversations = await Conversation.find({});
    const auditLogs = await AuditLog.find({});

    const totalMessages = conversations.reduce(
      (count, conversation) =>
        count + (Array.isArray(conversation.messages) ? conversation.messages.length : 0),
      0
    );

    res.json({
      totals: {
        totalUsers: users.length,
        verifiedUsers: users.filter((user) => {
          const totp = ensureUserTotpState(user);
          return Boolean(totp.isEnabled && totp.secret);
        }).length,
        recruiterUsers: users.filter((user) => user.role === "recruiter").length,
        suspendedUsers: users.filter((user) => user.isSuspended).length,
        resumesUploaded: users.filter((user) => Boolean(user.resume)).length,
        messagingReadyUsers: users.filter((user) => safeMessagingStatus(user).isConfigured).length,
        totalCompanies: companies.length,
        totalJobs: jobs.length,
        openJobs: jobs.filter((job) => job.status === "open").length,
        totalApplications: applications.length,
        totalConversations: conversations.length,
        totalMessages,
      },
      audit: {
        totalEntries: auditLogs.length,
        integrity: verifyAuditChain(auditLogs),
        recent: auditLogs.slice(-15).reverse(),
      },
    });
  });

  app.get("/api/admin/users", requireAuth, requireRole(["admin"]), async (req, res) => {
    const users = await User.find({});
    res.json({ users: users.map((user) => safeUserResponse(user)) });
  });

  app.patch(
    "/api/admin/users/:userId/suspension",
    requireAuth,
    requireRole(["admin"]),
    async (req, res) => {
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

      const target = await User.findOne({ id: targetUserId });
      if (!target) {
        res.status(404).json({ message: "Target user not found." });
        return;
      }

      target.isSuspended = isSuspended;
      target.updatedAt = new Date().toISOString();
      await appendAuditLog({
        actorUserId: req.auth.userId,
        action: isSuspended ? "ADMIN_SUSPENDED_USER" : "ADMIN_REACTIVATED_USER",
        targetUserId,
        metadata: { reason },
      });
      await target.save();

      res.json({
        message: isSuspended ? "User suspended." : "User reactivated.",
        user: safeUserResponse(target),
      });
    }
  );

  app.delete("/api/admin/users/:userId", requireAuth, requireRole(["admin"]), async (req, res) => {
    const targetUserId = String(req.params.userId || "").trim();
    if (!targetUserId) {
      res.status(400).json({ message: "Target user id is required." });
      return;
    }

    if (targetUserId === req.auth.userId) {
      res.status(400).json({ message: "Admin cannot delete their own account." });
      return;
    }

    const target = await deleteUserRecord(targetUserId);
    if (!target) {
      res.status(404).json({ message: "Target user not found." });
      return;
    }

    await appendAuditLog({
      actorUserId: req.auth.userId,
      action: "ADMIN_DELETED_USER",
      targetUserId,
      metadata: { email: target.email, role: target.role },
    });

    res.json({ message: "User deleted successfully." });
  });

  app.get("/api/admin/audit-logs", requireAuth, requireRole(["admin"]), async (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
    const search = sanitizeText(req.query.search || "", 80).toLowerCase();
    
    let query = {};
    if (search) {
      // Simplistic search for demo, MongoDB regex search
      query = { 
        $or: [
          { action: { $regex: search, $options: "i" } },
          { id: { $regex: search, $options: "i" } },
          { actorUserId: { $regex: search, $options: "i" } }
        ]
      };
    }

    const logs = await AuditLog.find(query).sort({ timestamp: -1 }).limit(limit);
    const allLogs = await AuditLog.find({}).sort({ timestamp: 1 });

    res.json({
      integrity: verifyAuditChain(allLogs),
      logs: logs,
    });
  });
}

module.exports = {
  registerAdminRoutes,
};

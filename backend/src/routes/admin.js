const { appendAuditLog, verifyAuditChain } = require("../audit");
const { readDb, writeDb } = require("../store");
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
  app.get("/api/admin/overview", requireAuth, requireRole(["admin"]), (req, res) => {
    const db = readDb();
    const totalMessages = db.conversations.reduce(
      (count, conversation) =>
        count + (Array.isArray(conversation.messages) ? conversation.messages.length : 0),
      0
    );

    res.json({
      totals: {
        totalUsers: db.users.length,
        verifiedUsers: db.users.filter((user) => {
          const totp = ensureUserTotpState(user);
          return Boolean(totp.isEnabled && totp.secret);
        }).length,
        recruiterUsers: db.users.filter((user) => user.role === "recruiter").length,
        suspendedUsers: db.users.filter((user) => user.isSuspended).length,
        resumesUploaded: db.users.filter((user) => Boolean(user.resume)).length,
        messagingReadyUsers: db.users.filter((user) => safeMessagingStatus(user).isConfigured).length,
        totalCompanies: db.companies.length,
        totalJobs: db.jobs.length,
        openJobs: db.jobs.filter((job) => job.status === "open").length,
        totalApplications: db.applications.length,
        totalConversations: db.conversations.length,
        totalMessages,
      },
      audit: {
        totalEntries: db.auditLogs.length,
        integrity: verifyAuditChain(db.auditLogs),
        recent: db.auditLogs.slice(-15).reverse(),
      },
    });
  });

  app.get("/api/admin/users", requireAuth, requireRole(["admin"]), (req, res) => {
    const db = readDb();
    res.json({ users: db.users.map((user) => safeUserResponse(user)) });
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

  app.delete("/api/admin/users/:userId", requireAuth, requireRole(["admin"]), (req, res) => {
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
  });

  app.get("/api/admin/audit-logs", requireAuth, requireRole(["admin"]), (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
    const search = sanitizeText(req.query.search || "", 80).toLowerCase();
    const db = readDb();
    let logs = db.auditLogs.slice().reverse();

    if (search) {
      logs = logs.filter((log) =>
        JSON.stringify(log).toLowerCase().includes(search)
      );
    }

    res.json({
      integrity: verifyAuditChain(db.auditLogs),
      logs: logs.slice(0, limit),
    });
  });
}

module.exports = {
  registerAdminRoutes,
};

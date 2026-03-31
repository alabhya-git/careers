const { v4: uuidv4 } = require("uuid");
const { appendAuditLog } = require("../audit");
const { readDb, writeDb } = require("../store");
const {
  CONVERSATION_TYPES,
  MAX_GROUP_MEMBERS,
  sanitizeText,
  isPlainObject,
  safeMessagingStatus,
  getMessagingDirectory,
  serializeConversation,
  serializeEncryptedMessage,
  findConversationById,
  requireAuth,
} = require("../portal-helpers");

function registerMessagingRoutes(app) {
  app.get("/api/messaging/identity", requireAuth, (req, res) => {
    const db = readDb();
    const user = db.users.find((item) => item.id === req.auth.userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json({
      identity: {
        ...safeMessagingStatus(user),
        publicKey: user.messaging?.publicKey || null,
        encryptedPrivateKey: user.messaging?.encryptedPrivateKey || null,
      },
    });
  });

  app.post("/api/messaging/identity", requireAuth, (req, res) => {
    const publicKey = req.body.publicKey;
    const encryptedPrivateKey = req.body.encryptedPrivateKey;
    const algorithm = sanitizeText(req.body.algorithm || "RSA-OAEP", 60);

    if (!isPlainObject(publicKey) || !isPlainObject(encryptedPrivateKey)) {
      res.status(400).json({
        message: "publicKey and encryptedPrivateKey objects are required.",
      });
      return;
    }

    if (
      JSON.stringify(publicKey).length > 12000 ||
      JSON.stringify(encryptedPrivateKey).length > 24000
    ) {
      res.status(400).json({ message: "Messaging key material exceeds size limits." });
      return;
    }

    const db = readDb();
    const user = db.users.find((item) => item.id === req.auth.userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    user.messaging.publicKey = publicKey;
    user.messaging.encryptedPrivateKey = encryptedPrivateKey;
    user.messaging.algorithm = algorithm || "RSA-OAEP";
    user.messaging.updatedAt = new Date().toISOString();
    user.updatedAt = user.messaging.updatedAt;
    appendAuditLog(db, {
      actorUserId: user.id,
      action: "MESSAGING_IDENTITY_UPSERTED",
      targetUserId: user.id,
      metadata: { algorithm: user.messaging.algorithm },
    });
    writeDb(db);

    res.status(201).json({
      message: "Messaging identity saved.",
      identity: {
        ...safeMessagingStatus(user),
        publicKey: user.messaging.publicKey,
        encryptedPrivateKey: user.messaging.encryptedPrivateKey,
      },
    });
  });

  app.get("/api/messaging/directory", requireAuth, (req, res) => {
    const db = readDb();
    const user = db.users.find((item) => item.id === req.auth.userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json({ contacts: getMessagingDirectory(db, user) });
  });

  app.get("/api/messaging/conversations", requireAuth, (req, res) => {
    const db = readDb();
    const conversations = db.conversations
      .filter(
        (conversation) =>
          Array.isArray(conversation.memberUserIds) &&
          conversation.memberUserIds.includes(req.auth.userId)
      )
      .sort((left, right) => {
        const rightDate = new Date(
          right.lastMessageAt || right.updatedAt || right.createdAt || 0
        ).getTime();
        const leftDate = new Date(
          left.lastMessageAt || left.updatedAt || left.createdAt || 0
        ).getTime();
        return rightDate - leftDate;
      })
      .map((conversation) => serializeConversation(db, conversation, req.auth.userId));

    res.json({ conversations });
  });

  app.post("/api/messaging/conversations", requireAuth, (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    if (!actor) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    const memberUserIds = Array.from(
      new Set([req.auth.userId, ...(Array.isArray(req.body.memberUserIds) ? req.body.memberUserIds : [])])
    )
      .map((value) => sanitizeText(value, 80))
      .filter(Boolean);
    const type =
      memberUserIds.length > 2
        ? "group"
        : sanitizeText(req.body.type || "direct", 20).toLowerCase();
    const title = sanitizeText(req.body.title, 120);

    if (!CONVERSATION_TYPES.has(type)) {
      res.status(400).json({ message: "Invalid conversation type." });
      return;
    }
    if (memberUserIds.length < 2) {
      res.status(400).json({ message: "Choose at least one other participant." });
      return;
    }
    if (memberUserIds.length > MAX_GROUP_MEMBERS) {
      res.status(400).json({
        message: `Conversations support up to ${MAX_GROUP_MEMBERS} members.`,
      });
      return;
    }
    if (type === "direct" && memberUserIds.length !== 2) {
      res.status(400).json({ message: "Direct conversations must have exactly 2 members." });
      return;
    }
    if (type === "group" && memberUserIds.length < 3) {
      res.status(400).json({ message: "Group conversations require at least 3 members." });
      return;
    }

    const allowedContactIds = new Set(getMessagingDirectory(db, actor).map((user) => user.id));
    const invalidMember = memberUserIds.find(
      (userId) => userId !== actor.id && !allowedContactIds.has(userId)
    );
    if (invalidMember) {
      res.status(403).json({
        message: "One or more selected members are not available for messaging.",
      });
      return;
    }

    const membersWithoutKeys = memberUserIds.find((userId) => {
      const candidate = db.users.find((user) => user.id === userId);
      return !candidate || !safeMessagingStatus(candidate).isConfigured;
    });
    if (membersWithoutKeys) {
      res.status(400).json({
        message:
          "Every participant must configure messaging encryption before joining a conversation.",
      });
      return;
    }

    const participantKeyMap = new Map();
    (Array.isArray(req.body.participantKeys) ? req.body.participantKeys : []).forEach((item) => {
      const userId = sanitizeText(item?.userId, 80);
      const encryptedKey = sanitizeText(item?.encryptedKey, 24000);
      const algorithm = sanitizeText(item?.algorithm || "RSA-OAEP", 80);
      if (userId && encryptedKey) {
        participantKeyMap.set(userId, { userId, encryptedKey, algorithm });
      }
    });

    const missingKeyBox = memberUserIds.find((userId) => !participantKeyMap.has(userId));
    if (missingKeyBox) {
      res.status(400).json({
        message: "Encrypted conversation keys are required for every participant.",
      });
      return;
    }

    if (type === "direct") {
      const sortedMembers = [...memberUserIds].sort();
      const existingConversation = db.conversations.find((conversation) => {
        const sortedExistingMembers = Array.isArray(conversation.memberUserIds)
          ? [...conversation.memberUserIds].sort()
          : [];
        return (
          conversation.type === "direct" &&
          sortedExistingMembers.length === 2 &&
          sortedExistingMembers[0] === sortedMembers[0] &&
          sortedExistingMembers[1] === sortedMembers[1]
        );
      });

      if (existingConversation) {
        res.json({
          message: "Conversation already exists.",
          conversation: serializeConversation(db, existingConversation, actor.id),
        });
        return;
      }
    }

    const timestamp = new Date().toISOString();
    const conversation = {
      id: uuidv4(),
      type,
      title: type === "group" ? title : "",
      createdByUserId: actor.id,
      memberUserIds,
      participantKeys: memberUserIds.map((userId) => ({
        ...participantKeyMap.get(userId),
        createdAt: timestamp,
      })),
      messages: [],
      createdAt: timestamp,
      updatedAt: timestamp,
      lastMessageAt: null,
    };

    db.conversations.push(conversation);
    appendAuditLog(db, {
      actorUserId: actor.id,
      action: "CONVERSATION_CREATED",
      targetUserId: actor.id,
      metadata: {
        conversationId: conversation.id,
        type: conversation.type,
        memberCount: memberUserIds.length,
      },
    });
    writeDb(db);

    res.status(201).json({
      message: "Encrypted conversation created.",
      conversation: serializeConversation(db, conversation, actor.id),
    });
  });

  app.get("/api/messaging/conversations/:conversationId/messages", requireAuth, (req, res) => {
    const db = readDb();
    const conversation = findConversationById(
      db,
      sanitizeText(req.params.conversationId, 80)
    );
    if (!conversation) {
      res.status(404).json({ message: "Conversation not found." });
      return;
    }
    if (
      !Array.isArray(conversation.memberUserIds) ||
      !conversation.memberUserIds.includes(req.auth.userId)
    ) {
      res.status(403).json({ message: "You do not have access to this conversation." });
      return;
    }

    res.json({
      conversation: serializeConversation(db, conversation, req.auth.userId),
      messages: (Array.isArray(conversation.messages) ? conversation.messages : []).map(
        (message) => serializeEncryptedMessage(db, message)
      ),
    });
  });

  app.post("/api/messaging/conversations/:conversationId/messages", requireAuth, (req, res) => {
    const ciphertext = sanitizeText(req.body.ciphertext, 32000);
    const iv = sanitizeText(req.body.iv, 300);
    const algorithm = sanitizeText(req.body.algorithm || "AES-GCM", 80);

    if (!ciphertext || !iv) {
      res.status(400).json({ message: "ciphertext and iv are required." });
      return;
    }

    const db = readDb();
    const conversation = findConversationById(
      db,
      sanitizeText(req.params.conversationId, 80)
    );
    if (!conversation) {
      res.status(404).json({ message: "Conversation not found." });
      return;
    }
    if (
      !Array.isArray(conversation.memberUserIds) ||
      !conversation.memberUserIds.includes(req.auth.userId)
    ) {
      res.status(403).json({ message: "You do not have access to this conversation." });
      return;
    }

    const now = new Date().toISOString();
    const message = {
      id: uuidv4(),
      senderUserId: req.auth.userId,
      ciphertext,
      iv,
      algorithm,
      sentAt: now,
    };

    conversation.messages = Array.isArray(conversation.messages)
      ? conversation.messages
      : [];
    conversation.messages.push(message);
    conversation.updatedAt = now;
    conversation.lastMessageAt = now;
    appendAuditLog(db, {
      actorUserId: req.auth.userId,
      action: "ENCRYPTED_MESSAGE_SENT",
      targetUserId: req.auth.userId,
      metadata: {
        conversationId: conversation.id,
        type: conversation.type,
        members: conversation.memberUserIds.length,
      },
    });
    writeDb(db);

    res.status(201).json({
      message: "Encrypted message stored.",
      encryptedMessage: serializeEncryptedMessage(db, message),
    });
  });
}

module.exports = {
  registerMessagingRoutes,
};

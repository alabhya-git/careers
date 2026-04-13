const { v4: uuidv4 } = require("uuid");
const { appendAuditLog } = require("../audit");
const User = require("../models/User");
const Conversation = require("../models/Conversation");
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
  app.get("/api/messaging/identity", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
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

  app.post("/api/messaging/identity", requireAuth, async (req, res) => {
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

    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    user.messaging.publicKey = publicKey;
    user.messaging.encryptedPrivateKey = encryptedPrivateKey;
    user.messaging.algorithm = algorithm || "RSA-OAEP";
    user.messaging.updatedAt = new Date().toISOString();
    user.updatedAt = user.messaging.updatedAt;
    user.markModified("messaging");
    await appendAuditLog({
      actorUserId: user.id,
      action: "MESSAGING_IDENTITY_UPSERTED",
      targetUserId: user.id,
      metadata: { algorithm: user.messaging.algorithm },
    });
    await user.save();

    res.status(201).json({
      message: "Messaging identity saved.",
      identity: {
        ...safeMessagingStatus(user),
        publicKey: user.messaging.publicKey,
        encryptedPrivateKey: user.messaging.encryptedPrivateKey,
      },
    });
  });

  app.get("/api/messaging/directory", requireAuth, async (req, res) => {
    const user = await User.findOne({ id: req.auth.userId });
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json({ contacts: await getMessagingDirectory(user) });
  });

  app.get("/api/messaging/conversations", requireAuth, async (req, res) => {
    const conversations = await Conversation.find({
      memberUserIds: req.auth.userId,
    }).sort({ lastMessageAt: -1, updatedAt: -1, createdAt: -1 });

    const serializedConversations = await Promise.all(
      conversations.map((conversation) => serializeConversation(conversation, req.auth.userId))
    );

    res.json({ conversations: serializedConversations });
  });

  app.post("/api/messaging/conversations", requireAuth, async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
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

    const directory = await getMessagingDirectory(actor);
    const allowedContactIds = new Set(directory.map((user) => user.id));
    const invalidMember = memberUserIds.find(
      (userId) => userId !== actor.id && !allowedContactIds.has(userId)
    );
    if (invalidMember) {
      res.status(403).json({
        message: "One or more selected members are not available for messaging.",
      });
      return;
    }

    for (const userId of memberUserIds) {
      const candidate = await User.findOne({ id: userId });
      if (!candidate || !safeMessagingStatus(candidate).isConfigured) {
        res.status(400).json({
          message:
            "Every participant must configure messaging encryption before joining a conversation.",
        });
        return;
      }
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
      const existingConversation = await Conversation.findOne({
        type: "direct",
        memberUserIds: { $all: sortedMembers, $size: 2 },
      });

      if (existingConversation) {
        res.json({
          message: "Conversation already exists.",
          conversation: await serializeConversation(existingConversation, actor.id),
        });
        return;
      }
    }

    const timestamp = new Date().toISOString();
    const conversation = new Conversation({
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
    });

    await conversation.save();
    await appendAuditLog({
      actorUserId: actor.id,
      action: "CONVERSATION_CREATED",
      targetUserId: actor.id,
      metadata: {
        conversationId: conversation.id,
        type: conversation.type,
        memberCount: memberUserIds.length,
      },
    });

    res.status(201).json({
      message: "Encrypted conversation created.",
      conversation: await serializeConversation(conversation, actor.id),
    });
  });

  app.get("/api/messaging/conversations/:conversationId/messages", requireAuth, async (req, res) => {
    const conversation = await findConversationById(
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

    const serializedMsgs = await Promise.all(
      (Array.isArray(conversation.messages) ? conversation.messages : []).map(
        (message) => serializeEncryptedMessage(message)
      )
    );

    res.json({
      conversation: await serializeConversation(conversation, req.auth.userId),
      messages: serializedMsgs,
    });
  });

  app.post("/api/messaging/conversations/:conversationId/messages", requireAuth, async (req, res) => {
    const ciphertext = sanitizeText(req.body.ciphertext, 32000);
    const iv = sanitizeText(req.body.iv, 300);
    const algorithm = sanitizeText(req.body.algorithm || "AES-GCM", 80);

    if (!ciphertext || !iv) {
      res.status(400).json({ message: "ciphertext and iv are required." });
      return;
    }

    const conversation = await findConversationById(
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
    conversation.markModified("messages");
    await appendAuditLog({
      actorUserId: req.auth.userId,
      action: "ENCRYPTED_MESSAGE_SENT",
      targetUserId: req.auth.userId,
      metadata: {
        conversationId: conversation.id,
        type: conversation.type,
        members: conversation.memberUserIds.length,
      },
    });
    await conversation.save();

    res.status(201).json({
      message: "Encrypted message stored.",
      encryptedMessage: await serializeEncryptedMessage(message),
    });
  });
}

module.exports = {
  registerMessagingRoutes,
};

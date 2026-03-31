import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createConversationKey,
  decryptConversationKeyForMember,
  decryptMessagePayload,
  encryptConversationKeyForMember,
  encryptMessageText,
  generateMessagingIdentity,
  unlockMessagingPrivateKey,
} from "../cryptoUtils";

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function getConversationLabel(conversation, currentUserId) {
  if (conversation.type === "group" && conversation.title) {
    return conversation.title;
  }

  const otherMembers = (conversation.members || []).filter(
    (member) => member.id !== currentUserId
  );

  return otherMembers.map((member) => member.profile?.name || member.email).join(", ");
}

function MessagingHub({ request, currentUser, onStatus, onError, clearFeedback }) {
  const [identity, setIdentity] = useState(null);
  const [contacts, setContacts] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [activeConversationId, setActiveConversationId] = useState("");
  const [messages, setMessages] = useState([]);
  const [setupPassphrase, setSetupPassphrase] = useState("");
  const [setupConfirm, setSetupConfirm] = useState("");
  const [unlockPassphrase, setUnlockPassphrase] = useState("");
  const [privateKey, setPrivateKey] = useState(null);
  const [composerTitle, setComposerTitle] = useState("");
  const [selectedContactIds, setSelectedContactIds] = useState([]);
  const [draft, setDraft] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const conversationKeyCache = useRef(new Map());

  const loadHub = useCallback(async () => {
    const [identityResponse, contactsResponse, conversationsResponse] = await Promise.all([
      request("/api/messaging/identity", { auth: true }),
      request("/api/messaging/directory", { auth: true }),
      request("/api/messaging/conversations", { auth: true }),
    ]);

    setIdentity(identityResponse.identity || null);
    setContacts(contactsResponse.contacts || []);
    setConversations(conversationsResponse.conversations || []);
    setActiveConversationId((previous) => {
      if (
        previous &&
        (conversationsResponse.conversations || []).some(
          (conversation) => conversation.id === previous
        )
      ) {
        return previous;
      }

      return conversationsResponse.conversations?.[0]?.id || "";
    });
  }, [request]);

  useEffect(() => {
    setIsLoading(true);
    loadHub()
      .catch((error) => onError(error.message))
      .finally(() => setIsLoading(false));
  }, [loadHub, onError]);

  const activeConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === activeConversationId) || null,
    [activeConversationId, conversations]
  );

  const getConversationKey = useCallback(
    async (conversation) => {
      if (!conversation) {
        throw new Error("Select a conversation first.");
      }

      if (conversationKeyCache.current.has(conversation.id)) {
        return conversationKeyCache.current.get(conversation.id);
      }

      if (!privateKey) {
        throw new Error("Unlock messaging to read encrypted conversations.");
      }

      const encryptedKey = conversation.participantKey?.encryptedKey;
      if (!encryptedKey) {
        throw new Error("Missing encrypted conversation key for this account.");
      }

      const conversationKey = await decryptConversationKeyForMember(privateKey, encryptedKey);
      conversationKeyCache.current.set(conversation.id, conversationKey);
      return conversationKey;
    },
    [privateKey]
  );

  const loadMessages = useCallback(
    async (conversationId) => {
      if (!conversationId || !privateKey) {
        setMessages([]);
        return;
      }

      const payload = await request(`/api/messaging/conversations/${conversationId}/messages`, {
        auth: true,
      });
      const conversation = payload.conversation;
      const conversationKey = await getConversationKey(conversation);
      const decryptedMessages = await Promise.all(
        (payload.messages || []).map(async (message) => ({
          ...message,
          plaintext: await decryptMessagePayload(conversationKey, message),
        }))
      );

      setMessages(decryptedMessages);
      setConversations((previous) =>
        previous.map((item) => (item.id === conversation.id ? conversation : item))
      );
    },
    [getConversationKey, privateKey, request]
  );

  useEffect(() => {
    if (!activeConversationId || !privateKey) {
      return;
    }

    setIsLoading(true);
    loadMessages(activeConversationId)
      .catch((error) => onError(error.message))
      .finally(() => setIsLoading(false));
  }, [activeConversationId, loadMessages, onError, privateKey]);

  const handleSetup = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (setupPassphrase.length < 8) {
      onError("Choose a messaging passphrase with at least 8 characters.");
      return;
    }

    if (setupPassphrase !== setupConfirm) {
      onError("Messaging passphrase confirmation does not match.");
      return;
    }

    setIsLoading(true);

    try {
      const generatedIdentity = await generateMessagingIdentity(setupPassphrase);
      const payload = await request("/api/messaging/identity", {
        method: "POST",
        auth: true,
        body: {
          publicKey: generatedIdentity.publicKey,
          encryptedPrivateKey: generatedIdentity.encryptedPrivateKey,
          algorithm: "RSA-OAEP",
        },
      });

      setPrivateKey(generatedIdentity.privateKey);
      setIdentity(payload.identity);
      setSetupPassphrase("");
      setSetupConfirm("");
      onStatus(payload.message || "Messaging identity configured.");
      await loadHub();
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnlock = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsLoading(true);

    try {
      const unlockedPrivateKey = await unlockMessagingPrivateKey(
        identity.encryptedPrivateKey,
        unlockPassphrase
      );
      setPrivateKey(unlockedPrivateKey);
      setUnlockPassphrase("");
      onStatus("Messaging unlocked for this session.");
    } catch (error) {
      onError("Could not unlock messaging. Check your passphrase.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateConversation = async () => {
    clearFeedback();

    if (!selectedContactIds.length) {
      onError("Select at least one contact to start a conversation.");
      return;
    }

    if (!identity?.publicKey) {
      onError("Messaging identity is not ready yet.");
      return;
    }

    setIsLoading(true);

    try {
      const members = [currentUser.id, ...selectedContactIds];
      const { rawKeyBase64 } = await createConversationKey();
      const selectedContacts = contacts.filter((contact) =>
        selectedContactIds.includes(contact.id)
      );

      const participantKeys = await Promise.all(
        [
          { id: currentUser.id, publicKey: identity.publicKey },
          ...selectedContacts.map((contact) => ({
            id: contact.id,
            publicKey: contact.messaging?.publicKey,
          })),
        ].map(async (member) => ({
          userId: member.id,
          encryptedKey: await encryptConversationKeyForMember(
            member.publicKey,
            rawKeyBase64
          ),
          algorithm: "RSA-OAEP",
        }))
      );

      const payload = await request("/api/messaging/conversations", {
        method: "POST",
        auth: true,
        body: {
          memberUserIds: selectedContactIds,
          title: members.length > 2 ? composerTitle : "",
          participantKeys,
        },
      });

      onStatus(payload.message || "Encrypted conversation created.");
      setComposerTitle("");
      setSelectedContactIds([]);
      await loadHub();
      setActiveConversationId(payload.conversation?.id || "");
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendMessage = async () => {
    clearFeedback();

    if (!activeConversation || !draft.trim()) {
      return;
    }

    setIsLoading(true);

    try {
      const conversationKey = await getConversationKey(activeConversation);
      const encryptedPayload = await encryptMessageText(conversationKey, draft.trim());
      const payload = await request(
        `/api/messaging/conversations/${activeConversation.id}/messages`,
        {
          method: "POST",
          auth: true,
          body: encryptedPayload,
        }
      );

      onStatus(payload.message || "Encrypted message sent.");
      setDraft("");
      await loadHub();
      await loadMessages(activeConversation.id);
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const availableContacts = contacts.filter((contact) => contact.messaging?.isConfigured);

  return (
    <section className="panel wide">
      <div className="section-heading">
        <div>
          <h2>Encrypted Messaging</h2>
          <p className="muted-copy">
            One-to-one and group messages are encrypted in the browser before storage.
          </p>
        </div>
      </div>

      {!identity?.isConfigured ? (
        <form className="stack-panel" onSubmit={handleSetup}>
          <h3>Set Up Messaging Encryption</h3>
          <label>
            Messaging Passphrase
            <input
              type="password"
              value={setupPassphrase}
              onChange={(event) => setSetupPassphrase(event.target.value)}
              required
            />
          </label>

          <label>
            Confirm Passphrase
            <input
              type="password"
              value={setupConfirm}
              onChange={(event) => setSetupConfirm(event.target.value)}
              required
            />
          </label>

          <button className="btn" type="submit" disabled={isLoading}>
            Generate Messaging Keys
          </button>
        </form>
      ) : !privateKey ? (
        <form className="stack-panel" onSubmit={handleUnlock}>
          <h3>Unlock Messaging</h3>
          <label>
            Messaging Passphrase
            <input
              type="password"
              value={unlockPassphrase}
              onChange={(event) => setUnlockPassphrase(event.target.value)}
              required
            />
          </label>

          <button className="btn" type="submit" disabled={isLoading}>
            Unlock Conversations
          </button>
        </form>
      ) : (
        <div className="messaging-layout">
          <aside className="stack-panel">
            <div className="stack-panel-heading">
              <h3>New Conversation</h3>
              <span className="badge">{availableContacts.length} contacts</span>
            </div>

            <label>
              Group Title
              <input
                value={composerTitle}
                onChange={(event) => setComposerTitle(event.target.value)}
                placeholder="Required when selecting 2+ contacts"
              />
            </label>

            <div className="selection-list">
              {availableContacts.map((contact) => (
                <label key={contact.id} className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={selectedContactIds.includes(contact.id)}
                    onChange={(event) =>
                      setSelectedContactIds((previous) =>
                        event.target.checked
                          ? [...previous, contact.id]
                          : previous.filter((id) => id !== contact.id)
                      )
                    }
                  />
                  <span>
                    {contact.profile?.name || contact.email}
                    <small>{contact.role}</small>
                  </span>
                </label>
              ))}
            </div>

            <button
              type="button"
              className="btn"
              onClick={handleCreateConversation}
              disabled={isLoading}
            >
              Start Encrypted Chat
            </button>

            <div className="stack-panel-heading">
              <h3>Conversations</h3>
              <span className="badge">{conversations.length}</span>
            </div>

            <div className="card-stack">
              {conversations.map((conversation) => (
                <button
                  key={conversation.id}
                  type="button"
                  className={`conversation-card ${
                    conversation.id === activeConversationId ? "active" : ""
                  }`}
                  onClick={() => setActiveConversationId(conversation.id)}
                >
                  <strong>{getConversationLabel(conversation, currentUser.id)}</strong>
                  <span>{formatDate(conversation.lastMessageAt || conversation.createdAt)}</span>
                </button>
              ))}
            </div>
          </aside>

          <div className="stack-panel">
            {activeConversation ? (
              <>
                <div className="stack-panel-heading">
                  <h3>{getConversationLabel(activeConversation, currentUser.id)}</h3>
                  <span className="badge">{activeConversation.type}</span>
                </div>

                <div className="message-list">
                  {messages.map((message) => (
                    <article
                      key={message.id}
                      className={`message-bubble ${
                        message.senderUserId === currentUser.id ? "mine" : ""
                      }`}
                    >
                      <strong>{message.sender?.profile?.name || message.sender?.email}</strong>
                      <p>{message.plaintext}</p>
                      <span>{formatDate(message.sentAt)}</span>
                    </article>
                  ))}

                  {!messages.length ? (
                    <p className="muted-copy">No messages yet in this encrypted conversation.</p>
                  ) : null}
                </div>

                <label>
                  Message
                  <textarea
                    rows="4"
                    value={draft}
                    onChange={(event) => setDraft(event.target.value)}
                    placeholder="Write a message for this conversation"
                  />
                </label>

                <button
                  type="button"
                  className="btn"
                  onClick={handleSendMessage}
                  disabled={isLoading || !draft.trim()}
                >
                  Send Encrypted Message
                </button>
              </>
            ) : (
              <p className="muted-copy">
                Start a conversation from the left panel to begin secure recruiter-candidate messaging.
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export default MessagingHub;

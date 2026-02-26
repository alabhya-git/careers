const { v4: uuidv4 } = require("uuid");
const { sha256 } = require("./security");

function appendAuditLog(
  db,
  { actorUserId = null, action, targetUserId = null, metadata = {} }
) {
  const timestamp = new Date().toISOString();
  const prevHash = db.auditLogs.length
    ? db.auditLogs[db.auditLogs.length - 1].hash
    : "GENESIS";
  const record = {
    id: uuidv4(),
    timestamp,
    actorUserId,
    action,
    targetUserId,
    metadata,
    prevHash,
  };

  record.hash = sha256(
    `${record.prevHash}|${record.id}|${record.timestamp}|${record.actorUserId}|${record.action}|${record.targetUserId}|${JSON.stringify(record.metadata)}`
  );

  db.auditLogs.push(record);
  return record;
}

function verifyAuditChain(logs) {
  for (let index = 0; index < logs.length; index += 1) {
    const current = logs[index];
    const expectedPrev = index === 0 ? "GENESIS" : logs[index - 1].hash;
    const expectedHash = sha256(
      `${expectedPrev}|${current.id}|${current.timestamp}|${current.actorUserId}|${current.action}|${current.targetUserId}|${JSON.stringify(current.metadata)}`
    );

    if (current.prevHash !== expectedPrev || current.hash !== expectedHash) {
      return { valid: false, brokenAt: index };
    }
  }

  return { valid: true, brokenAt: null };
}

module.exports = {
  appendAuditLog,
  verifyAuditChain,
};

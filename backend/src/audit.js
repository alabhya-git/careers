const { v4: uuidv4 } = require("uuid");
const {
  sha256,
  isAuditPkiEnabled,
  signAuditChainLink,
  verifyAuditChainLink,
} = require("./security");

const GENESIS_POINTER = "GENESIS";
const CHAIN_VERSION_HMAC = "HMAC_SHA256_V2";
const CHAIN_VERSION_PKI = "PKI_RSA_SHA256_V3";

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

function buildBasePayload(record) {
  return `${record.id}|${record.timestamp}|${record.actorUserId}|${record.action}|${record.targetUserId}|${stableStringify(record.metadata || {})}`;
}

function computeLegacyHash(record, prevHash) {
  return sha256(`${prevHash}|${buildBasePayload(record)}`);
}

function computeSignedPayload(prevSignature, payloadDigest) {
  return `${prevSignature}|${payloadDigest}`;
}

function computeSignedChainSignature(prevSignature, payloadDigest) {
  return signAuditChainLink(computeSignedPayload(prevSignature, payloadDigest));
}

function getPreviousPointer(logs) {
  if (!logs.length) {
    return GENESIS_POINTER;
  }
  const previous = logs[logs.length - 1];
  return previous.signature || previous.hash || GENESIS_POINTER;
}

function appendAuditLog(
  db,
  { actorUserId = null, action, targetUserId = null, metadata = {} }
) {
  const timestamp = new Date().toISOString();
  const prevHash = getPreviousPointer(db.auditLogs);
  const record = {
    id: uuidv4(),
    timestamp,
    actorUserId,
    action,
    targetUserId,
    metadata,
    prevHash,
  };

  record.chainVersion = isAuditPkiEnabled()
    ? CHAIN_VERSION_PKI
    : CHAIN_VERSION_HMAC;
  record.payloadDigest = sha256(buildBasePayload(record));
  record.signature = computeSignedChainSignature(record.prevHash, record.payloadDigest);
  record.hash = record.signature;

  db.auditLogs.push(record);
  return record;
}

function verifyAuditChain(logs) {
  for (let index = 0; index < logs.length; index += 1) {
    const current = logs[index];
    const previous = index === 0 ? null : logs[index - 1];
    const expectedPrev = previous
      ? previous.signature || previous.hash || GENESIS_POINTER
      : GENESIS_POINTER;
    const basePayload = buildBasePayload(current);
    const legacyExpectedHash = computeLegacyHash(current, expectedPrev);
    const expectedPayloadDigest = sha256(basePayload);
    const expectedSignature = computeSignedChainSignature(
      expectedPrev,
      expectedPayloadDigest
    );

    if (
      current.chainVersion === CHAIN_VERSION_HMAC ||
      current.chainVersion === CHAIN_VERSION_PKI
    ) {
      const chainVersion = current.chainVersion || CHAIN_VERSION_HMAC;
      const signaturePayload = computeSignedPayload(
        expectedPrev,
        expectedPayloadDigest
      );
      const isValid =
        current.prevHash === expectedPrev &&
        current.payloadDigest === expectedPayloadDigest &&
        verifyAuditChainLink(signaturePayload, current.signature, chainVersion) &&
        (chainVersion === CHAIN_VERSION_HMAC
          ? current.signature === expectedSignature
          : typeof current.signature === "string" && current.signature.length > 0) &&
        current.hash === current.signature;
      if (!isValid) {
        return {
          valid: false,
          brokenAt: index,
          chainVersion,
          reason: "Signed audit entry failed signature verification.",
        };
      }
      continue;
    }

    const legacyValid =
      current.prevHash === expectedPrev && current.hash === legacyExpectedHash;
    if (!legacyValid) {
      return {
        valid: false,
        brokenAt: index,
        chainVersion: "LEGACY_SHA256_V1",
        reason: "Legacy audit entry hash mismatch.",
      };
    }
  }

  return {
    valid: true,
    brokenAt: null,
    chainVersion: isAuditPkiEnabled() ? CHAIN_VERSION_PKI : CHAIN_VERSION_HMAC,
    reason: null,
  };
}

module.exports = {
  appendAuditLog,
  verifyAuditChain,
};

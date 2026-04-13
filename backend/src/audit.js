const { v4: uuidv4 } = require("uuid");
const {
  sha256,
  isAuditPkiEnabled,
  signAuditChainLink,
  verifyAuditChainLink,
} = require("./security");
const { AUDIT_BLOCKCHAIN_DIFFICULTY } = require("./config");

const GENESIS_POINTER = "GENESIS";
const CHAIN_VERSION_HMAC = "HMAC_SHA256_V2";
const CHAIN_VERSION_PKI = "PKI_RSA_SHA256_V3";
const BLOCKCHAIN_VERSION = "AUDIT_BLOCKCHAIN_V1";

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

function buildBlockMaterial(record, previousBlockHash, nonce) {
  return `${record.blockchainVersion}|${record.blockIndex}|${previousBlockHash}|${record.payloadDigest}|${record.signature}|${record.timestamp}|${nonce}`;
}

function mineBlockHash(record, previousBlockHash, difficulty) {
  const targetPrefix = "0".repeat(Math.max(0, difficulty));
  let nonce = 0;

  while (true) {
    const blockHash = sha256(buildBlockMaterial(record, previousBlockHash, nonce));
    if (!targetPrefix || blockHash.startsWith(targetPrefix)) {
      return { blockHash, nonce };
    }
    nonce += 1;
  }
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
  record.blockchainVersion = BLOCKCHAIN_VERSION;
  record.blockIndex = db.auditLogs.length;
  record.previousBlockHash = db.auditLogs.length
    ? db.auditLogs[db.auditLogs.length - 1].blockHash || GENESIS_POINTER
    : GENESIS_POINTER;
  record.blockDifficulty = AUDIT_BLOCKCHAIN_DIFFICULTY;
  const mined = mineBlockHash(
    record,
    record.previousBlockHash,
    record.blockDifficulty
  );
  record.blockNonce = mined.nonce;
  record.blockHash = mined.blockHash;

  db.auditLogs.push(record);
  return record;
}

function verifyAuditChain(logs) {
  const targetDifficulty = Math.max(0, AUDIT_BLOCKCHAIN_DIFFICULTY);

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
          blockchainVersion: current.blockchainVersion || null,
          reason: "Signed audit entry failed signature verification.",
        };
      }
    } else {
      const legacyValid =
        current.prevHash === expectedPrev && current.hash === legacyExpectedHash;
      if (!legacyValid) {
        return {
          valid: false,
          brokenAt: index,
          chainVersion: "LEGACY_SHA256_V1",
          blockchainVersion: current.blockchainVersion || null,
          reason: "Legacy audit entry hash mismatch.",
        };
      }
    }

    if (current.blockchainVersion === BLOCKCHAIN_VERSION) {
      const expectedBlockIndex = index;
      const expectedPreviousBlockHash = previous
        ? previous.blockHash || GENESIS_POINTER
        : GENESIS_POINTER;
      const expectedDifficulty = Number.isFinite(Number(current.blockDifficulty))
        ? Math.max(0, Number(current.blockDifficulty))
        : targetDifficulty;
      const recomputedBlockHash = sha256(
        buildBlockMaterial(
          current,
          expectedPreviousBlockHash,
          Number(current.blockNonce || 0)
        )
      );
      const hasRequiredWork =
        expectedDifficulty <= 0 ||
        recomputedBlockHash.startsWith("0".repeat(expectedDifficulty));
      const blockValid =
        current.blockIndex === expectedBlockIndex &&
        current.previousBlockHash === expectedPreviousBlockHash &&
        current.blockHash === recomputedBlockHash &&
        hasRequiredWork;
      if (!blockValid) {
        return {
          valid: false,
          brokenAt: index,
          chainVersion: current.chainVersion || "UNKNOWN",
          blockchainVersion: BLOCKCHAIN_VERSION,
          reason: "Blockchain audit integrity verification failed.",
        };
      }
    }
  }

  return {
    valid: true,
    brokenAt: null,
    chainVersion: isAuditPkiEnabled() ? CHAIN_VERSION_PKI : CHAIN_VERSION_HMAC,
    blockchainVersion: BLOCKCHAIN_VERSION,
    reason: null,
  };
}

module.exports = {
  appendAuditLog,
  verifyAuditChain,
};

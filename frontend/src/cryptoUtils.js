const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PBKDF2_ITERATIONS = 250000;

function getWebCrypto() {
  if (typeof window === "undefined" || !window.crypto?.subtle) {
    throw new Error("Web Crypto is not available in this browser.");
  }

  return window.crypto;
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

async function derivePassphraseKey(passphrase, salt, iterations = PBKDF2_ITERATIONS) {
  const cryptoApi = getWebCrypto();
  const passphraseKey = await cryptoApi.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return cryptoApi.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    passphraseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function importPublicKey(publicKeyJwk) {
  return getWebCrypto().subtle.importKey(
    "jwk",
    publicKeyJwk,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

export async function generateMessagingIdentity(passphrase) {
  const cryptoApi = getWebCrypto();
  const keyPair = await cryptoApi.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKey = await cryptoApi.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKey = await cryptoApi.subtle.exportKey("jwk", keyPair.privateKey);

  const salt = cryptoApi.getRandomValues(new Uint8Array(16));
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const derivedKey = await derivePassphraseKey(passphrase, salt);
  const ciphertext = await cryptoApi.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    derivedKey,
    encoder.encode(JSON.stringify(privateKey))
  );

  return {
    publicKey,
    privateKey: keyPair.privateKey,
    encryptedPrivateKey: {
      ciphertext: toBase64(ciphertext),
      iv: toBase64(iv.buffer),
      salt: toBase64(salt.buffer),
      iterations: PBKDF2_ITERATIONS,
      algorithm: "AES-GCM/PBKDF2",
      format: "jwk",
    },
  };
}

export async function unlockMessagingPrivateKey(bundle, passphrase) {
  if (!bundle?.ciphertext || !bundle?.iv || !bundle?.salt) {
    throw new Error("Encrypted private key material is incomplete.");
  }

  const cryptoApi = getWebCrypto();
  const decrypted = await cryptoApi.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(fromBase64(bundle.iv)),
    },
    await derivePassphraseKey(
      passphrase,
      new Uint8Array(fromBase64(bundle.salt)),
      Number(bundle.iterations) || PBKDF2_ITERATIONS
    ),
    fromBase64(bundle.ciphertext)
  );

  return cryptoApi.subtle.importKey(
    "jwk",
    JSON.parse(decoder.decode(decrypted)),
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

export async function createConversationKey() {
  const cryptoApi = getWebCrypto();
  const key = await cryptoApi.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  const rawKey = await cryptoApi.subtle.exportKey("raw", key);
  return {
    key,
    rawKeyBase64: toBase64(rawKey),
  };
}

export async function encryptConversationKeyForMember(publicKeyJwk, rawKeyBase64) {
  const encrypted = await getWebCrypto().subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    await importPublicKey(publicKeyJwk),
    fromBase64(rawKeyBase64)
  );

  return toBase64(encrypted);
}

export async function decryptConversationKeyForMember(privateKey, encryptedKey) {
  const decryptedRaw = await getWebCrypto().subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    fromBase64(encryptedKey)
  );

  return getWebCrypto().subtle.importKey(
    "raw",
    decryptedRaw,
    {
      name: "AES-GCM",
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessageText(conversationKey, text) {
  const cryptoApi = getWebCrypto();
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const ciphertext = await cryptoApi.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    conversationKey,
    encoder.encode(text)
  );

  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv.buffer),
    algorithm: "AES-GCM",
  };
}

export async function decryptMessagePayload(conversationKey, payload) {
  const decrypted = await getWebCrypto().subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(fromBase64(payload.iv)),
    },
    conversationKey,
    fromBase64(payload.ciphertext)
  );

  return decoder.decode(decrypted);
}

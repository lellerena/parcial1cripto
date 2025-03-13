import nacl from "tweetnacl";
import chacha from "chacha";
import naclUtil from "tweetnacl-util";

// Generate a random nonce (24 bytes for Salsa20, 12 bytes for ChaCha20)
export function generateNonce(n: number = 24): Uint8Array {
  return nacl.randomBytes(n); // Nonce de 192 bits
}

// Encrypt using Salsa20
export function encryptSalsa20(
  text: string,
  key: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = generateNonce(24); // Salsa20 uses 24-byte nonce
  const messageUint8 = naclUtil.decodeUTF8(text);
  const ciphertext = nacl.secretbox(messageUint8, nonce, key);
  return { ciphertext, nonce };
}

// Decrypt using Salsa20
export function decryptSalsa20(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
): string | null {
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  return decrypted ? naclUtil.encodeUTF8(decrypted) : null;
}

// Encrypt using ChaCha20
export function encryptChaCha20(
  text: string,
  key: Buffer,
): { ciphertext: Buffer; nonce: Buffer } {
  const nonce = Buffer.from(generateNonce(12)); // ChaCha20 uses 12-byte nonce
  const cipher = chacha.createCipher(key, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(text, "utf8")),
    cipher.final(),
  ]);
  return { ciphertext, nonce };
}

// Decrypt using ChaCha20
export function decryptChaCha20(
  ciphertext: Buffer,
  nonce: Buffer,
  key: Buffer,
): string {
  const cipher = chacha.createDecipher(key, nonce);
  const decrypted = Buffer.concat([cipher.update(ciphertext), cipher.final()]);
  return decrypted.toString("utf8");
}

export function encryptStreamCipher(
  text: string,
  key: string,
  cipher: "Salsa20" | "ChaCha20",
): string {
  if (cipher === "Salsa20") {
    const keyUint8 = new TextEncoder().encode(key);
    const { ciphertext, nonce } = encryptSalsa20(text, keyUint8);
    return JSON.stringify({ ciphertext, nonce });
  } else {
    const keyBuffer = Buffer.from(key, "base64");
    const { ciphertext, nonce } = encryptChaCha20(text, keyBuffer);
    return JSON.stringify({ ciphertext, nonce });
  }
}

export function decryptStreamCipher(
  ciphertext: string,
  key: string,
  cipher: "Salsa20" | "ChaCha20",
): string {
  const { ciphertext: cipherBuffer, nonce } = JSON.parse(ciphertext);
  if (cipher === "Salsa20") {
    const keyUint8 = new TextEncoder().encode(key);
    return decryptSalsa20(cipherBuffer, nonce, keyUint8) || "";
  } else {
    const keyBuffer = Buffer.from(key, "base64");
    return decryptChaCha20(cipherBuffer, nonce, keyBuffer);
  }
}

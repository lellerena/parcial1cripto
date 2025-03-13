import * as CryptoJS from "crypto-js";

// Encrypt using AES (Scenario 2)
export function encryptAES(
  text: string,
  key: string,
  mode: "ECB" | "CBC" | "CTR",
  technique: "none" | "double" | "triple" | "whitening",
  additionalKeys: string[],
): string {
  let encrypted = text;

  // Apply the selected security technique
  switch (technique) {
    case "none":
      // Single encryption
      encrypted = CryptoJS.AES.encrypt(encrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString();
      break;

    case "double":
      // Double encryption with two keys
      encrypted = CryptoJS.AES.encrypt(encrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString();

      if (additionalKeys.length > 0) {
        encrypted = CryptoJS.AES.encrypt(encrypted, additionalKeys[0], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString();
      }
      break;

    case "triple":
      // Triple encryption with three keys
      encrypted = CryptoJS.AES.encrypt(encrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString();

      if (additionalKeys.length > 0) {
        encrypted = CryptoJS.AES.encrypt(encrypted, additionalKeys[0], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString();
      }

      if (additionalKeys.length > 1) {
        encrypted = CryptoJS.AES.encrypt(encrypted, additionalKeys[1], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString();
      }
      break;

    case "whitening":
      // Key whitening (XOR with additional material before and after)
      // This is a simplified implementation
      if (additionalKeys.length > 0) {
        const whitenedKey = CryptoJS.PBKDF2(key, additionalKeys[0], {
          keySize: 256 / 32,
          iterations: 1000,
        });

        encrypted = CryptoJS.AES.encrypt(encrypted, whitenedKey, {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString();
      } else {
        encrypted = CryptoJS.AES.encrypt(encrypted, key, {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString();
      }
      break;
  }

  return encrypted;
}

// Decrypt using AES (Scenario 2)
export function decryptAES(
  ciphertext: string,
  key: string,
  mode: "ECB" | "CBC" | "CTR",
  technique: "none" | "double" | "triple" | "whitening",
  additionalKeys: string[],
): string {
  let decrypted = ciphertext;

  // Apply the reverse of the selected security technique
  switch (technique) {
    case "none":
      // Single decryption
      decrypted = CryptoJS.AES.decrypt(decrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString(CryptoJS.enc.Utf8);
      break;

    case "double":
      // Double decryption with two keys (in reverse order)
      if (additionalKeys.length > 0) {
        decrypted = CryptoJS.AES.decrypt(decrypted, additionalKeys[0], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString(CryptoJS.enc.Utf8);
      }

      decrypted = CryptoJS.AES.decrypt(decrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString(CryptoJS.enc.Utf8);
      break;

    case "triple":
      // Triple decryption with three keys (in reverse order)
      if (additionalKeys.length > 1) {
        decrypted = CryptoJS.AES.decrypt(decrypted, additionalKeys[1], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString(CryptoJS.enc.Utf8);
      }

      if (additionalKeys.length > 0) {
        decrypted = CryptoJS.AES.decrypt(decrypted, additionalKeys[0], {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString(CryptoJS.enc.Utf8);
      }

      decrypted = CryptoJS.AES.decrypt(decrypted, key, {
        mode: getCryptoJSMode(mode),
        padding: CryptoJS.pad.Pkcs7,
      }).toString(CryptoJS.enc.Utf8);
      break;

    case "whitening":
      // Key whitening (reverse the process)
      if (additionalKeys.length > 0) {
        const whitenedKey = CryptoJS.PBKDF2(key, additionalKeys[0], {
          keySize: 256 / 32,
          iterations: 1000,
        });

        decrypted = CryptoJS.AES.decrypt(decrypted, whitenedKey, {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString(CryptoJS.enc.Utf8);
      } else {
        decrypted = CryptoJS.AES.decrypt(decrypted, key, {
          mode: getCryptoJSMode(mode),
          padding: CryptoJS.pad.Pkcs7,
        }).toString(CryptoJS.enc.Utf8);
      }
      break;
  }

  return decrypted;
}

// Helper to get CryptoJS mode from string
export function getCryptoJSMode(mode: "ECB" | "CBC" | "CTR") {
  switch (mode) {
    case "ECB":
      return CryptoJS.mode.ECB;
    case "CBC":
      return CryptoJS.mode.CBC;
    case "CTR":
      return CryptoJS.mode.CTR;
    default:
      return CryptoJS.mode.CBC;
  }
}

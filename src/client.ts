import { io } from "socket.io-client";
import crypto from "crypto";
import readline from "readline";

// Conectar con el servidor
const socket = io("http://localhost:3000");

let sharedKey: Buffer | null = null;

// Funciones de cifrado y descifrado con ChaCha20
function encryptMessage(
  message: string,
  nonce: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  if (!sharedKey) throw new Error("Clave aún no recibida");
  const cipher = crypto.createCipheriv("chacha20-poly1305", sharedKey, nonce, {
    authTagLength: 16,
  });
  const encrypted = Buffer.concat([
    cipher.update(message, "utf8"),
    cipher.final(),
  ]);
  return { ciphertext: encrypted, tag: cipher.getAuthTag() };
}

function decryptMessage(
  ciphertext: Buffer,
  nonce: Buffer,
  tag: Buffer,
): string | null {
  if (!sharedKey) return null;
  try {
    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305",
      sharedKey,
      nonce,
      { authTagLength: 16 },
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

// Configurar entrada de usuario
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Recibir la clave del servidor
socket.on("shared_key", (data) => {
  sharedKey = Buffer.from(data.key, "base64");
  console.log("🔑 Clave compartida recibida");

  askForMessage();
});

// Enviar mensaje cifrado al servidor
function sendMessage(message: string) {
  if (!sharedKey) {
    console.error("❌ Clave aún no recibida");
    return;
  }

  const nonce = crypto.randomBytes(12);
  const { ciphertext, tag } = encryptMessage(message, nonce);

  socket.emit("encrypted_message", {
    ciphertext: ciphertext.toString("base64"),
    nonce: nonce.toString("base64"),
    tag: tag.toString("base64"),
  });
}

// Recibir y descifrar respuesta del servidor
socket.on("encrypted_response", (data) => {
  const { ciphertext, nonce, tag } = data;
  const decryptedResponse = decryptMessage(
    Buffer.from(ciphertext, "base64"),
    Buffer.from(nonce, "base64"),
    Buffer.from(tag, "base64"),
  );

  console.log(`🛡️ Respuesta del servidor: ${decryptedResponse}`);
  askForMessage();
});

// Pedir mensaje al usuario
function askForMessage() {
  rl.question("📝 Escribe un mensaje: ", (message) => {
    if (message.toLowerCase() === "exit") {
      console.log("👋 Saliendo...");
      socket.disconnect();
      rl.close();
      return;
    }
    sendMessage(message);
  });
}

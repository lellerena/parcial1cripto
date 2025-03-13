import express from "express";
import http from "http";
import { Server } from "socket.io";
import crypto from "crypto";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

// 🔐 Generar clave secreta de 256 bits
const key = crypto.randomBytes(32);
const encodedKey = key.toString("base64");

// Funciones de cifrado y descifrado con ChaCha20
function encryptMessage(
  message: string,
  nonce: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {
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
  try {
    const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: 16,
    });
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

io.on("connection", (socket) => {
  console.log("Cliente conectado");

  // Enviar la clave al cliente
  socket.emit("shared_key", { key: encodedKey });

  socket.on("encrypted_message", (data) => {
    const { ciphertext, nonce, tag } = data;
    const decryptedMessage = decryptMessage(
      Buffer.from(ciphertext, "base64"),
      Buffer.from(nonce, "base64"),
      Buffer.from(tag, "base64"),
    );

    console.log("Mensaje recibido (descifrado):", decryptedMessage);

    // Responder con un mensaje cifrado
    const response = `Servidor recibió: "${decryptedMessage}"`;
    const responseNonce = crypto.randomBytes(12);
    const { ciphertext: encryptedResponse, tag: responseTag } = encryptMessage(
      response,
      responseNonce,
    );

    socket.emit("encrypted_response", {
      ciphertext: encryptedResponse.toString("base64"),
      nonce: responseNonce.toString("base64"),
      tag: responseTag.toString("base64"),
    });
  });

  socket.on("disconnect", () => {
    console.log("Cliente desconectado");
  });
});

server.listen(3000, () => {
  console.log("Servidor escuchando en el puerto 3000");
});

import express from "express";
import http from "http";
import { Server } from "socket.io";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import crypto from "crypto";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

// Generar claves para ambos algoritmos
const salsa20Key = nacl.randomBytes(32);
const encodedSalsa20Key = naclUtil.encodeBase64(salsa20Key);

const chacha20Key = crypto.randomBytes(32);
const encodedChacha20Key = chacha20Key.toString("base64");

// Funciones de cifrado y descifrado para Salsa20
function encryptMessageSalsa20(message: string, nonce: Uint8Array): Uint8Array {
  return nacl.secretbox(naclUtil.decodeUTF8(message), nonce, salsa20Key);
}

function decryptMessageSalsa20(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
): string | null {
  const decrypted = nacl.secretbox.open(ciphertext, nonce, salsa20Key);
  return decrypted ? naclUtil.encodeUTF8(decrypted) : null;
}

// Funciones de cifrado y descifrado para ChaCha20
function encryptMessageChaCha20(
  message: string,
  nonce: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = crypto.createCipheriv(
    "chacha20-poly1305",
    chacha20Key,
    nonce,
    {
      authTagLength: 16,
    },
  );
  const encrypted = Buffer.concat([
    cipher.update(message, "utf8"),
    cipher.final(),
  ]);
  return { ciphertext: encrypted, tag: cipher.getAuthTag() };
}

function decryptMessageChaCha20(
  ciphertext: Buffer,
  nonce: Buffer,
  tag: Buffer,
): string | null {
  try {
    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305",
      chacha20Key,
      nonce,
      {
        authTagLength: 16,
      },
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

io.on("connection", (socket) => {
  console.log("Cliente conectado");
  let selectedAlgorithm: string | null = null;

  // Manejar la selección del algoritmo
  socket.on("select_algorithm", (data) => {
    const { algorithm } = data;
    selectedAlgorithm = algorithm;
    console.log(`Cliente eligió algoritmo: ${algorithm}`);

    // Enviar la clave correspondiente según el algoritmo seleccionado
    if (algorithm === "salsa20") {
      socket.emit("shared_key", {
        key: encodedSalsa20Key,
        algorithm: "salsa20",
      });
    } else if (algorithm === "chacha20") {
      socket.emit("shared_key", {
        key: encodedChacha20Key,
        algorithm: "chacha20",
      });
    } else {
      socket.emit("error", { message: "Algoritmo no soportado" });
    }
  });

  // Manejar mensajes cifrados con Salsa20
  socket.on("salsa20_message", (data) => {
    const { ciphertext, nonce } = data;
    const decryptedMessage = decryptMessageSalsa20(
      naclUtil.decodeBase64(ciphertext),
      naclUtil.decodeBase64(nonce),
    );

    console.log("Mensaje Salsa20 recibido (descifrado):", decryptedMessage);

    // Enviar respuesta cifrada con Salsa20
    const response = `Servidor recibió mensaje Salsa20: "${decryptedMessage}"`;
    const responseNonce = nacl.randomBytes(24);
    const encryptedResponse = encryptMessageSalsa20(response, responseNonce);

    socket.emit("salsa20_response", {
      ciphertext: naclUtil.encodeBase64(encryptedResponse),
      nonce: naclUtil.encodeBase64(responseNonce),
    });
  });

  // Manejar mensajes cifrados con ChaCha20
  socket.on("chacha20_message", (data) => {
    const { ciphertext, nonce, tag } = data;
    const decryptedMessage = decryptMessageChaCha20(
      Buffer.from(ciphertext, "base64"),
      Buffer.from(nonce, "base64"),
      Buffer.from(tag, "base64"),
    );

    console.log("Mensaje ChaCha20 recibido (descifrado):", decryptedMessage);

    // Responder con un mensaje cifrado con ChaCha20
    const response = `Servidor recibió mensaje ChaCha20: "${decryptedMessage}"`;
    const responseNonce = crypto.randomBytes(12);
    const { ciphertext: encryptedResponse, tag: responseTag } =
      encryptMessageChaCha20(response, responseNonce);

    socket.emit("chacha20_response", {
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

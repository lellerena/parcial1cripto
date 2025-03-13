import express from "express";
import http from "http";
import { Server } from "socket.io";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

// 🔐 Generar clave secreta única para la sesión
const key = nacl.randomBytes(32);
const encodedKey = naclUtil.encodeBase64(key); // Convertir clave a string para enviarla al cliente

// Funciones de cifrado y descifrado
function encryptMessage(message: string, nonce: Uint8Array): Uint8Array {
  return nacl.secretbox(naclUtil.decodeUTF8(message), nonce, key);
}

function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
): string | null {
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  return decrypted ? naclUtil.encodeUTF8(decrypted) : null;
}

io.on("connection", (socket) => {
  console.log("Cliente conectado");

  // Enviar la clave compartida al cliente
  socket.emit("shared_key", { key: encodedKey });

  socket.on("encrypted_message", (data) => {
    const { ciphertext, nonce } = data;
    const decryptedMessage = decryptMessage(
      naclUtil.decodeBase64(ciphertext),
      naclUtil.decodeBase64(nonce),
    );

    console.log("Mensaje recibido (descifrado):", decryptedMessage);

    // Enviar respuesta cifrada
    const response = `Servidor recibió: "${decryptedMessage}"`;
    const responseNonce = nacl.randomBytes(24);
    const encryptedResponse = encryptMessage(response, responseNonce);

    socket.emit("encrypted_response", {
      ciphertext: naclUtil.encodeBase64(encryptedResponse),
      nonce: naclUtil.encodeBase64(responseNonce),
    });
  });

  socket.on("disconnect", () => {
    console.log("Cliente desconectado");
  });
});

server.listen(3000, () => {
  console.log("Servidor escuchando en el puerto 3000");
});

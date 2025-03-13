import express from "express";
import { createServer } from "http";
import { Server, Socket } from "socket.io";
import nacl from "tweetnacl";
import crypto from "crypto";

import dotenv from "dotenv";
import { Message } from "./types";
import { decryptStreamCipher } from "./crypto/stream-cipher";

dotenv.config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// 🔹 Función para generar una clave de flujo (Salsa20/ChaCha20)
const generateStreamCipherKey = (cipher: "Salsa20" | "ChaCha20") => {
  return nacl.randomBytes(cipher === "Salsa20" ? 32 : 32); // 256 bits
};

// 🔹 Función para generar clave AES de 256 bits
const generateAESKey = () => nacl.randomBytes(32); // 256 bits

// 🔹 Manejo de conexiones con los clientes
io.on("connection", (socket: Socket) => {
  console.log(`Client connected: ${socket.id}`);
  let key: any = "";

  socket.on(
    "init-stream-cipher",
    (cipher: { cipher: "Salsa20" | "ChaCha20" }) => {
      console.log(cipher);
      if (cipher.cipher !== "Salsa20" && cipher.cipher !== "ChaCha20") {
        console.log("Invalid stream cipher selection");
        return socket.emit("error", "Invalid stream cipher selection");
      }

      key = generateStreamCipherKey(cipher.cipher);
      console.log(`🔑 Generated ${cipher} key for ${socket.id}: ${key}`);

      socket.emit("symmetric-key", key.toString("base64"));
    },
  );

  socket.on("message", (message: Message) => {
    // {"text":"U2FsdGVkX1+U1ai4sVNDc8TPDAG+5EcbZgBWlizeh9E=","encrypted":true,"scenario":1,"cipher":"Salsa20"}
    console.log(message);
    if (message.encrypted) {
      try {
        const text = JSON.parse(message.text);
        console.log(text);
        //   convert buffer to string
        const cipherText = Buffer.from(text.ciphertext).toString("base64");
        console.log(cipherText);
        message.text = decryptStreamCipher(
          message.text,
          key,
          message.cipher as "Salsa20" | "ChaCha20",
        );
      } catch (error) {
        console.error(`Error decrypting message: ${error}`);
        return socket.emit("error", "Error decrypting message");
      }
    }

    console.log(`📨 Message from ${socket.id}: ${message.text}`);
    io.emit("message", message);
  });

  socket.on(
    "aes-mode-selection",
    ({
      mode,
      securityTechnique,
    }: {
      mode: "ECB" | "CBC" | "CTR";
      securityTechnique: "none" | "double" | "triple" | "whitening";
    }) => {
      if (!["ECB", "CBC", "CTR"].includes(mode)) {
        return socket.emit("error", "Invalid AES mode selection");
      }

      const additionalKeys =
        securityTechnique === "none"
          ? []
          : ([
              crypto.randomBytes(32).toString("hex"),
              securityTechnique !== "double"
                ? crypto.randomBytes(32).toString("hex")
                : undefined,
            ].filter(Boolean) as string[]);

      console.log(`🔑 AES ${mode} with ${securityTechnique} for ${socket.id}`);

      if (additionalKeys.length) {
        socket.emit("additional-keys", additionalKeys);
      }

      socket.emit("block-cipher-initialized");
    },
  );

  socket.on("disconnect", (reason) => {
    console.log(`Client disconnected: ${socket.id}, Reason: ${reason}`);
    key = "";
  });
});

// 🔹 Iniciar el servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Socket.IO Server running on http://localhost:${PORT}`);
});

import crypto from "crypto";
import { io } from "socket.io-client";
import readline from "readline";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Función auxiliar para aplicar técnicas de seguridad adicionales
function applySecurityTechnique(
  key: Buffer,
  technique: "none" | "double" | "triple" | "whitening",
): Buffer {
  switch (technique) {
    case "double":
      return crypto.createHash("sha256").update(key).digest();
    case "triple":
      return crypto.createHash("sha512").update(key).digest().subarray(0, 32);
    case "whitening":
      return Buffer.from(key.map((byte, index) => byte ^ index % 256));
    default:
      return key;
  }
}

rl.question("🔑 Ingresa la clave compartida: ", (keyInput) => {
  const sharedKey = Buffer.from(keyInput, "hex");

  const socket = io("http://localhost:3000");

  socket.on("connect", () => {
    console.log("✅ Conectado al servidor");

    rl.question("📌 Ingresa el modo AES (ecb, cbc, ctr): ", (mode) => {
      rl.question(
        "🛡️ Ingresa la técnica de seguridad (none, double, triple, whitening): ",
        (technique) => {
          socket.emit("config", { mode, technique });

          rl.setPrompt("💬 Escribe tu mensaje: ");
          rl.prompt();
          rl.on("line", (message) => {
            const iv = crypto.randomBytes(16);
            const secureKey = applySecurityTechnique(
              sharedKey,
              technique as any,
            );
            let cipher;

            if (mode === "cbc" || mode === "ctr") {
              cipher = crypto.createCipheriv(`aes-256-${mode}`, secureKey, iv);
            } else {
              cipher = crypto.createCipheriv("aes-256-ecb", secureKey, null);
            }

            let encryptedMessage = cipher.update(message, "utf-8", "hex");
            encryptedMessage += cipher.final("hex");

            socket.emit("message", {
              encryptedMessage,
              iv: iv.toString("hex"),
            });
            console.log("📤 Mensaje enviado cifrado:", encryptedMessage);
          });
        },
      );
    });
  });
});

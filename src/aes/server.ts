import crypto from "crypto";
import { Server } from "socket.io";

const io = new Server(3000);

const sharedKey = crypto.randomBytes(32); // La clave debe ser compartida con el cliente de otra manera.
console.log("🔑 Clave generada por el servidor:", sharedKey.toString("hex"));

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

io.on("connection", (socket) => {
  console.log("✅ Cliente conectado");

  let mode: "ecb" | "cbc" | "ctr";
  let technique: "none" | "double" | "triple" | "whitening";

  socket.on("config", (config) => {
    mode = config.mode;
    technique = config.technique;
    console.log(`📡 Cliente seleccionó AES-${mode} con técnica ${technique}`);
  });

  socket.on("message", ({ encryptedMessage, iv }) => {
    const secureKey = applySecurityTechnique(sharedKey, technique);
    let decipher;

    if (mode === "cbc" || mode === "ctr") {
      decipher = crypto.createDecipheriv(
        `aes-256-${mode}`,
        secureKey,
        Buffer.from(iv, "hex"),
      );
    } else {
      decipher = crypto.createDecipheriv("aes-256-ecb", secureKey, null);
    }

    try {
      let decryptedMessage = decipher.update(encryptedMessage, "hex", "utf-8");
      decryptedMessage += decipher.final("utf-8");
      console.log("🔓 Mensaje descifrado:", decryptedMessage);
    } catch (error) {
      console.error("❌ Error al descifrar:", error.message);
    }
  });
});

console.log("🚀 Servidor en puerto 3000");

import { io } from "socket.io-client";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import crypto from "crypto";
import readline from "readline";

// Conectar con el servidor
const socket = io("http://localhost:3000");

// Configurar entrada de consola
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Variables para almacenar claves
let salsa20Key: Uint8Array | null = null;
let chacha20Key: Buffer | null = null;
let selectedAlgorithm: string | null = null;

// Funciones para Salsa20
function encryptMessageSalsa20(message: string, nonce: Uint8Array): Uint8Array {
  if (!salsa20Key) throw new Error("Clave Salsa20 no recibida");
  return nacl.secretbox(naclUtil.decodeUTF8(message), nonce, salsa20Key);
}

function decryptMessageSalsa20(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
): string | null {
  if (!salsa20Key) return null;
  const decrypted = nacl.secretbox.open(ciphertext, nonce, salsa20Key);
  return decrypted ? naclUtil.encodeUTF8(decrypted) : null;
}

// Funciones para ChaCha20
function encryptMessageChaCha20(
  message: string,
  nonce: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  if (!chacha20Key) throw new Error("Clave ChaCha20 no recibida");
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
  if (!chacha20Key) return null;
  try {
    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305",
      chacha20Key,
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

// Solicitar al usuario que elija el algoritmo
function askForAlgorithm() {
  rl.question(
    "Elige el algoritmo de cifrado (salsa20 o chacha20): ",
    (algorithm) => {
      if (
        algorithm.toLowerCase() !== "salsa20" &&
        algorithm.toLowerCase() !== "chacha20"
      ) {
        console.log("❌ Algoritmo no válido. Intenta de nuevo.");
        askForAlgorithm();
        return;
      }

      selectedAlgorithm = algorithm.toLowerCase();
      console.log(`🔐 Has elegido ${selectedAlgorithm}`);

      // Enviar selección al servidor
      socket.emit("select_algorithm", { algorithm: selectedAlgorithm });
    },
  );
}

// Recibir la clave compartida según el algoritmo
socket.on("shared_key", (data) => {
  const { key, algorithm } = data;

  if (algorithm === "salsa20") {
    salsa20Key = naclUtil.decodeBase64(key);
    console.log("🔑 Clave Salsa20 recibida");
  } else if (algorithm === "chacha20") {
    chacha20Key = Buffer.from(key, "base64");
    console.log("🔑 Clave ChaCha20 recibida");
  }

  // Iniciar la entrada de mensajes
  askForMessage();
});

// Enviar mensaje cifrado según el algoritmo seleccionado
function sendMessage(message: string) {
  if (selectedAlgorithm === "salsa20") {
    if (!salsa20Key) {
      console.error("❌ Clave Salsa20 aún no recibida");
      return;
    }

    const nonce = nacl.randomBytes(24);
    const encryptedMessage = encryptMessageSalsa20(message, nonce);

    socket.emit("salsa20_message", {
      ciphertext: naclUtil.encodeBase64(encryptedMessage),
      nonce: naclUtil.encodeBase64(nonce),
    });
  } else if (selectedAlgorithm === "chacha20") {
    if (!chacha20Key) {
      console.error("❌ Clave ChaCha20 aún no recibida");
      return;
    }

    const nonce = crypto.randomBytes(12);
    const { ciphertext, tag } = encryptMessageChaCha20(message, nonce);

    socket.emit("chacha20_message", {
      ciphertext: ciphertext.toString("base64"),
      nonce: nonce.toString("base64"),
      tag: tag.toString("base64"),
    });
  }
}

// Recibir respuestas cifradas con Salsa20
socket.on("salsa20_response", (data) => {
  const { ciphertext, nonce } = data;
  const decryptedResponse = decryptMessageSalsa20(
    naclUtil.decodeBase64(ciphertext),
    naclUtil.decodeBase64(nonce),
  );

  console.log(`🛡️ Respuesta del servidor (Salsa20): ${decryptedResponse}`);
  askForMessage();
});

// Recibir respuestas cifradas con ChaCha20
socket.on("chacha20_response", (data) => {
  const { ciphertext, nonce, tag } = data;
  const decryptedResponse = decryptMessageChaCha20(
    Buffer.from(ciphertext, "base64"),
    Buffer.from(nonce, "base64"),
    Buffer.from(tag, "base64"),
  );

  console.log(`🛡️ Respuesta del servidor (ChaCha20): ${decryptedResponse}`);
  askForMessage();
});

// Manejar errores
socket.on("error", (data) => {
  console.error(`❌ Error: ${data.message}`);
  askForAlgorithm();
});

// Solicitar mensaje al usuario
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

// Iniciar selección de algoritmo al conectar
socket.on("connect", () => {
  console.log("Conectado al servidor");
  askForAlgorithm();
});

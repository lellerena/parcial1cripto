import { io } from "socket.io-client";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import readline from "readline";

// Conectar con el servidor
const socket = io("http://localhost:3000");

let sharedKey: Uint8Array | null = null; // Clave compartida

// Funciones de cifrado y descifrado
function encryptMessage(message: string, nonce: Uint8Array): Uint8Array {
  return sharedKey
    ? nacl.secretbox(naclUtil.decodeUTF8(message), nonce, sharedKey)
    : new Uint8Array();
}

function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
): string | null {
  if (!sharedKey) return null;
  const decrypted = nacl.secretbox.open(ciphertext, nonce, sharedKey);
  return decrypted ? naclUtil.encodeUTF8(decrypted) : null;
}

// Configurar entrada de consola
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Recibir la clave del servidor
socket.on("shared_key", (data) => {
  sharedKey = naclUtil.decodeBase64(data.key);
  console.log("🔑 Clave compartida recibida");

  // Iniciar la entrada de usuario
  askForMessage();
});

// Enviar mensaje cifrado al servidor
function sendMessage(message: string) {
  if (!sharedKey) {
    console.error("❌ Clave aún no recibida");
    return;
  }

  const nonce = nacl.randomBytes(24);
  const encryptedMessage = encryptMessage(message, nonce);

  socket.emit("encrypted_message", {
    ciphertext: naclUtil.encodeBase64(encryptedMessage),
    nonce: naclUtil.encodeBase64(nonce),
  });
}

// Recibir y descifrar respuesta del servidor
socket.on("encrypted_response", (data) => {
  const { ciphertext, nonce } = data;
  const decryptedResponse = decryptMessage(
    naclUtil.decodeBase64(ciphertext),
    naclUtil.decodeBase64(nonce),
  );

  console.log(`🛡️ Respuesta del servidor: ${decryptedResponse}`);
  askForMessage(); // Pedir otro mensaje
});

// Preguntar al usuario por un mensaje
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

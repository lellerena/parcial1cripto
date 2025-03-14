import { io } from 'socket.io-client'
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import crypto from 'crypto'
import readline from 'readline'
import {
    decryptMessageChaCha20,
    decryptMessageSalsa20,
    encryptMessageChaCha20,
    encryptMessageSalsa20
} from '../crypto/stream-cipher'

// Conectar con el servidor
const socket = io('http://localhost:3000')

// Configurar entrada de consola
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
})

// Variables para almacenar claves
let salsa20Key: Uint8Array | null = null
let chacha20Key: Buffer | null = null
let selectedAlgorithm: string | null = null

// Solicitar al usuario que elija el algoritmo
function askForAlgorithm() {
    rl.question(
        'Elige el algoritmo de cifrado (salsa20 o chacha20): ',
        (algorithm) => {
            if (
                algorithm.toLowerCase() !== 'salsa20' &&
                algorithm.toLowerCase() !== 'chacha20'
            ) {
                console.log('❌ Algoritmo no válido. Intenta de nuevo.')
                askForAlgorithm()
                return
            }

            selectedAlgorithm = algorithm.toLowerCase()
            console.log(`🔐 Has elegido ${selectedAlgorithm}`)

            // Enviar selección al servidor
            socket.emit('select_algorithm', { algorithm: selectedAlgorithm })
        }
    )
}

// Recibir la clave compartida según el algoritmo
socket.on('shared_key', (data) => {
    const { key, algorithm } = data

    if (algorithm === 'salsa20') {
        salsa20Key = naclUtil.decodeBase64(key)
        console.log('🔑 Clave Salsa20 recibida')
    } else if (algorithm === 'chacha20') {
        chacha20Key = Buffer.from(key, 'base64')
        console.log('🔑 Clave ChaCha20 recibida')
    }

    // Iniciar la entrada de mensajes
    askForMessage()
})

// Enviar mensaje cifrado según el algoritmo seleccionado
function sendMessage(message: string) {
    if (selectedAlgorithm === 'salsa20') {
        if (!salsa20Key) {
            console.error('❌ Clave Salsa20 aún no recibida')
            return
        }

        const nonce = nacl.randomBytes(24)
        const encryptedMessage = encryptMessageSalsa20(
            message,
            salsa20Key,
            nonce
        )

        socket.emit('salsa20_message', {
            ciphertext: naclUtil.encodeBase64(encryptedMessage),
            nonce: naclUtil.encodeBase64(nonce)
        })
    } else if (selectedAlgorithm === 'chacha20') {
        if (!chacha20Key) {
            console.error('❌ Clave ChaCha20 aún no recibida')
            return
        }

        const nonce = crypto.randomBytes(12)
        const { ciphertext, tag } = encryptMessageChaCha20(
            message,
            chacha20Key,
            nonce
        )

        socket.emit('chacha20_message', {
            ciphertextcha: ciphertext.toString('base64'),
            nonce: nonce.toString('base64'),
            tag: tag.toString('base64')
        })
    }
}

// Recibir respuestas cifradas con Salsa20
socket.on('salsa20_response', (data) => {
    const { ciphertext, nonce } = data
    const decryptedResponse = decryptMessageSalsa20(
        naclUtil.decodeBase64(ciphertext),
        salsa20Key,
        naclUtil.decodeBase64(nonce)
    )

    console.log(`🛡️ Respuesta del servidor (Salsa20): ${decryptedResponse}`)
    askForMessage()
})

// Recibir respuestas cifradas con ChaCha20
socket.on('chacha20_response', (data) => {
    const { ciphertext, nonce, tag } = data
    const decryptedResponse = decryptMessageChaCha20(
        Buffer.from(ciphertext, 'base64'),
        chacha20Key,
        Buffer.from(nonce, 'base64'),
        Buffer.from(tag, 'base64')
    )

    console.log(`🛡️ Respuesta del servidor (ChaCha20): ${decryptedResponse}`)
    askForMessage()
})

// Manejar errores
socket.on('error', (data) => {
    console.error(`❌ Error: ${data.message}`)
    askForAlgorithm()
})

// Solicitar mensaje al usuario
function askForMessage() {
    rl.question('📝 Escribe un mensaje: ', (message) => {
        if (message.toLowerCase() === 'exit') {
            console.log('👋 Saliendo...')
            socket.disconnect()
            rl.close()
            return
        }
        sendMessage(message)
    })
}

// Iniciar selección de algoritmo al conectar
socket.on('connect', () => {
    console.log('Conectado al servidor')
    askForAlgorithm()
})

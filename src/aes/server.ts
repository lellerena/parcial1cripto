// server.ts
import { GoogleGenerativeAI } from '@google/generative-ai'
import { Server } from 'socket.io'
import nacl from 'tweetnacl'
import util from 'tweetnacl-util'

const io = new Server(3000)

// Generar clave aleatoria de 32 bytes (256 bits)
const sharedKey = nacl.randomBytes(32)
console.log(
    '🔑 Clave simétrica principal (256 bits):',
    util.encodeBase64(sharedKey)
)
console.log('⚠️ Comparta esta clave con el cliente por un canal seguro')

// Llaves adicionales que se generarán según la técnica seleccionada
let doubleKey: Uint8Array | null = null
let tripleKey: Uint8Array | null = null
let whiteningKey: Uint8Array | null = null

// Access your API key as an environment variable (see "Set up your API key" above)
const genAI = new GoogleGenerativeAI('AIzaSyApScEEWXYebBFgMtKpfQuZ6V2ZhpHH0y8')

// The Gemini 1.5 models are versatile and work with most use cases
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' })

// Función para aplicar técnicas de seguridad
function applySecurityTechnique(
    key: Uint8Array,
    technique: 'none' | 'double' | 'triple' | 'whitening',
    additionalKeys?: {
        doubleKey?: Uint8Array
        tripleKey?: Uint8Array
        whiteningKey?: Uint8Array
    }
): Uint8Array {
    switch (technique) {
        case 'double':
            // Usar la clave adicional para el cifrado doble
            return additionalKeys?.doubleKey || key
        case 'triple':
            // Usar la clave adicional para el cifrado triple
            return additionalKeys?.tripleKey || key
        case 'whitening':
            // Aplicar whitening con la clave adicional
            return additionalKeys?.whiteningKey || key
        default:
            return key
    }
}

// Función para cifrar con el modo CBC (para enviar llaves adicionales)
function encryptWithCBC(
    message: Uint8Array,
    key: Uint8Array
): { encrypted: string; nonce: string } {
    const nonce = nacl.randomBytes(24)
    const encrypted = nacl.secretbox(message, nonce, key)
    return {
        encrypted: util.encodeBase64(encrypted),
        nonce: util.encodeBase64(nonce)
    }
}

// Función para descifrar con modo CBC
function decryptWithCBC(
    encryptedBase64: string,
    nonceBase64: string,
    key: Uint8Array
): Uint8Array | null {
    try {
        const encrypted = util.decodeBase64(encryptedBase64)
        const nonce = util.decodeBase64(nonceBase64)

        const decrypted = nacl.secretbox.open(encrypted, nonce, key)
        if (!decrypted) return null

        return decrypted
    } catch (error) {
        console.error('Error al descifrar:', error)
        return null
    }
}

// Función para cifrar mensajes según el modo seleccionado
function createEncryptor(mode: string, key: Uint8Array, iv?: Uint8Array) {
    return {
        encrypt: (message: string): { encrypted: string; nonce: string } => {
            const messageUint8 = util.decodeUTF8(message)
            let nonce: Uint8Array

            if (mode === 'ecb') {
                // En ECB usamos un nonce fijo (simulación)
                nonce = new Uint8Array(24).fill(0)
            } else if (mode === 'cbc' || mode === 'ctr') {
                // Para CBC y CTR usamos IV aleatorio
                nonce = iv || nacl.randomBytes(24)
            } else {
                // Por defecto nonce aleatorio
                nonce = nacl.randomBytes(24)
            }

            const encrypted = nacl.secretbox(messageUint8, nonce, key)
            return {
                encrypted: util.encodeBase64(encrypted),
                nonce: util.encodeBase64(nonce)
            }
        },

        decrypt: (
            encryptedBase64: string,
            nonceBase64: string
        ): string | null => {
            try {
                const encrypted = util.decodeBase64(encryptedBase64)
                const nonce = util.decodeBase64(nonceBase64)

                const decrypted = nacl.secretbox.open(encrypted, nonce, key)
                if (!decrypted) return null

                return util.encodeUTF8(decrypted)
            } catch (error) {
                console.error('Error al descifrar:', error)
                return null
            }
        }
    }
}

io.on('connection', (socket) => {
    console.log('✅ Cliente conectado')
    let clientMode: 'ecb' | 'cbc' | 'ctr' = 'cbc'
    let clientTechnique: 'none' | 'double' | 'triple' | 'whitening' = 'none'
    let securityKeysSet = false
    const chat = model.startChat({
        history: [
            {
                role: 'user',
                parts: [
                    {
                        text: 'responde de manera divertida a lo que te diga, limitate a 100 caracteres por respuesta, puedes usar emojis para expresarte'
                    }
                ]
            }
        ],
        generationConfig: {
            maxOutputTokens: 100
        }
    })

    socket.on('config', (config) => {
        clientMode = config.mode
        clientTechnique = config.technique
        console.log(
            `📡 Cliente seleccionó AES-${clientMode} con técnica ${clientTechnique}`
        )

        socket.emit('additionalKeys', {
            keys: []
        })

        // Generar llaves adicionales según la técnica seleccionada
        if (clientTechnique !== 'none' && !securityKeysSet) {
            // Crear llaves adicionales según la técnica
            if (clientTechnique === 'double') {
                doubleKey = nacl.randomBytes(32)
                console.log('🔑 Clave para cifrado doble generada')

                // Enviar la clave adicional cifrada con CBC y la clave compartida

                socket.emit('additionalKeys', {
                    keys: [doubleKey]
                })
            } else if (clientTechnique === 'triple') {
                tripleKey = nacl.randomBytes(32)
                const secondTripleKey = nacl.randomBytes(32)
                console.log('🔑 Claves para cifrado triple generadas')

                socket.emit('additionalKeys', {
                    keys: [tripleKey, secondTripleKey]
                })
            } else if (clientTechnique === 'whitening') {
                whiteningKey = nacl.randomBytes(32)
                console.log('🔑 Clave para blanqueamiento generada')

                // Enviar la clave de blanqueamiento cifrada
                const { encrypted, nonce } = encryptWithCBC(
                    whiteningKey,
                    sharedKey
                )
                socket.emit('additionalKeys', {
                    whiteningKey: { encrypted, nonce }
                })
            }

            securityKeysSet = true
        }
    })

    socket.on('message', async ({ encryptedMessage, nonce }) => {
        // Determinar qué clave usar basado en la técnica seleccionada
        let keyToUse: Uint8Array

        if (clientTechnique === 'double' && doubleKey) {
            keyToUse = doubleKey
        } else if (clientTechnique === 'triple' && tripleKey) {
            keyToUse = tripleKey
        } else if (clientTechnique === 'whitening' && whiteningKey) {
            // Aplicar whitening a la clave compartida
            keyToUse = new Uint8Array(32)
            for (let i = 0; i < 32; i++) {
                keyToUse[i] = sharedKey[i] ^ whiteningKey[i]
            }
        } else {
            keyToUse = sharedKey
        }

        // Descifrar el mensaje con la clave apropiada
        const decryptor = createEncryptor(clientMode, keyToUse)

        try {
            const decryptedMessage = decryptor.decrypt(encryptedMessage, nonce)
            if (decryptedMessage) {
                console.log('🔓 Mensaje descifrado:', decryptedMessage)
                const result = await chat.sendMessage(decryptedMessage)
                const res = await result.response
                const randomResponse = res.text()
            } else {
                console.error(
                    '❌ Error al descifrar: verificación de autenticación fallida'
                )
            }
        } catch (error) {
            console.error('❌ Error al descifrar:', error.message)
        }
    })
})

console.log('🚀 Servidor en puerto 3000')

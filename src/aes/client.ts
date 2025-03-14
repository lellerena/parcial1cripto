// client.ts
import { io } from 'socket.io-client'
import readline from 'readline'
import nacl from 'tweetnacl'
import util from 'tweetnacl-util'
import { createEncryptor, decryptWithCBC } from '../crypto/block-cipher'

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
})

// Almacenamiento para llaves adicionales
let doubleKey: Uint8Array | null = null
let tripleKey1: Uint8Array | null = null
let tripleKey2: Uint8Array | null = null
let whiteningKey: Uint8Array | null = null

rl.question('🔑 Ingresa la clave compartida (en base64): ', (keyInput) => {
    const sharedKey = util.decodeBase64(keyInput)
    const socket = io('http://localhost:3000')

    socket.on('connect', () => {
        console.log('✅ Conectado al servidor')

        rl.question(
            '📌 Ingresa el modo de operación (ecb, cbc, ctr): ',
            (mode) => {
                rl.question(
                    '🛡️ Ingresa la técnica de seguridad (none, double, triple, whitening): ',
                    (technique) => {
                        socket.emit('config', { mode, technique })

                        // Esperar llaves adicionales si se seleccionó una técnica de seguridad
                        if (technique !== 'none') {
                            console.log(
                                '⏳ Esperando llaves adicionales del servidor...'
                            )
                        } else {
                            startChatting()
                        }

                        // Escuchar llaves adicionales del servidor
                        socket.on('additionalKeys', (keys) => {
                            console.log(
                                '🔐 Recibidas llaves adicionales cifradas'
                            )

                            if (keys.doubleKey) {
                                const decrypted = decryptWithCBC(
                                    keys.doubleKey.encrypted,
                                    keys.doubleKey.nonce,
                                    sharedKey
                                )
                                if (decrypted) {
                                    doubleKey = decrypted
                                    console.log(
                                        '✅ Clave para cifrado doble descifrada correctamente'
                                    )
                                }
                            }

                            if (keys.tripleKey1 && keys.tripleKey2) {
                                const decrypted1 = decryptWithCBC(
                                    keys.tripleKey1.encrypted,
                                    keys.tripleKey1.nonce,
                                    sharedKey
                                )
                                const decrypted2 = decryptWithCBC(
                                    keys.tripleKey2.encrypted,
                                    keys.tripleKey2.nonce,
                                    sharedKey
                                )

                                if (decrypted1 && decrypted2) {
                                    tripleKey1 = decrypted1
                                    tripleKey2 = decrypted2
                                    console.log(
                                        '✅ Claves para cifrado triple descifradas correctamente'
                                    )
                                }
                            }

                            if (keys.whiteningKey) {
                                const decrypted = decryptWithCBC(
                                    keys.whiteningKey.encrypted,
                                    keys.whiteningKey.nonce,
                                    sharedKey
                                )
                                if (decrypted) {
                                    whiteningKey = decrypted
                                    console.log(
                                        '✅ Clave para blanqueamiento descifrada correctamente'
                                    )
                                }
                            }

                            startChatting()
                        })

                        function startChatting() {
                            rl.setPrompt('💬 Escribe tu mensaje: ')
                            rl.prompt()
                            rl.on('line', (message) => {
                                // Configurar el cifrador con el modo y técnica seleccionados
                                const encryptor = createEncryptor(
                                    mode,
                                    sharedKey,
                                    technique as any,
                                    {
                                        doubleKey,
                                        tripleKey1,
                                        tripleKey2,
                                        whiteningKey
                                    }
                                )

                                // Cifrar y enviar el mensaje
                                const { encrypted: encryptedMessage, nonce } =
                                    encryptor.encrypt(message)

                                socket.emit('message', {
                                    encryptedMessage,
                                    nonce
                                })
                                console.log('📤 Mensaje enviado cifrado')
                                rl.prompt()
                            })
                        }
                    }
                )
            }
        )
    })
})

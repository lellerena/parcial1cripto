import nacl from 'tweetnacl'
import util from 'tweetnacl-util'

// Función para descifrar con modo CBC
export function decryptWithCBC(
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

// Función para cifrar mensajes según el modo y técnica seleccionados
export function createEncryptor(
    mode: string,
    baseKey: Uint8Array,
    technique: 'none' | 'double' | 'triple' | 'whitening',
    additionalKeys: {
        doubleKey?: Uint8Array | null
        tripleKey1?: Uint8Array | null
        tripleKey2?: Uint8Array | null
        whiteningKey?: Uint8Array | null
    } = {}
) {
    return {
        encrypt: (message: string): { encrypted: string; nonce: string } => {
            const messageUint8 = util.decodeUTF8(message)
            let nonce: Uint8Array
            let keyToUse: Uint8Array

            // Determinar qué clave usar basado en la técnica
            if (technique === 'double' && additionalKeys.doubleKey) {
                keyToUse = additionalKeys.doubleKey
            } else if (technique === 'triple' && additionalKeys.tripleKey1) {
                // Para el triple cifrado usaríamos múltiples claves en secuencia
                // en una implementación real. Aquí simplificamos usando la primera.
                keyToUse = additionalKeys.tripleKey1
            } else if (
                technique === 'whitening' &&
                additionalKeys.whiteningKey
            ) {
                // Aplicar whitening a la clave base
                keyToUse = new Uint8Array(32)
                for (let i = 0; i < 32; i++) {
                    keyToUse[i] = baseKey[i] ^ additionalKeys.whiteningKey[i]
                }
            } else {
                keyToUse = baseKey
            }

            // Generar nonce según el modo
            if (mode === 'ecb') {
                nonce = new Uint8Array(24).fill(0)
            } else {
                nonce = nacl.randomBytes(24)
            }

            const encrypted = nacl.secretbox(messageUint8, nonce, keyToUse)
            return {
                encrypted: util.encodeBase64(encrypted),
                nonce: util.encodeBase64(nonce)
            }
        }
    }
}

export function encryptWithCBC(
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

import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import crypto from 'crypto'

// Funciones de cifrado y descifrado para Salsa20
export function encryptMessageSalsa20(
    message: string,
    salsa20Key: Uint8Array,
    nonce: Uint8Array
): Uint8Array {
    return nacl.secretbox(naclUtil.decodeUTF8(message), nonce, salsa20Key)
}

export function decryptMessageSalsa20(
    ciphertext: Uint8Array,
    salsa20Key: Uint8Array,
    nonce: Uint8Array
): string | null {
    const decrypted = nacl.secretbox.open(ciphertext, nonce, salsa20Key)
    return decrypted ? naclUtil.encodeUTF8(decrypted) : null
}

// Funciones de cifrado y descifrado para ChaCha20
export function encryptMessageChaCha20(
    message: string,
    chacha20Key: Buffer,
    nonce: Buffer
): { ciphertext: Buffer; tag: Buffer } {
    const cipher = crypto.createCipheriv(
        'chacha20-poly1305',
        chacha20Key,
        nonce,
        {
            authTagLength: 16
        }
    )
    const encrypted = Buffer.concat([
        cipher.update(message, 'utf8'),
        cipher.final()
    ])
    return { ciphertext: encrypted, tag: cipher.getAuthTag() }
}

export function decryptMessageChaCha20(
    ciphertext: Buffer,
    chacha20Key: Buffer,
    nonce: Buffer,
    tag: Buffer
): string | null {
    try {
        const decipher = crypto.createDecipheriv(
            'chacha20-poly1305',
            chacha20Key,
            nonce,
            {
                authTagLength: 16
            }
        )
        decipher.setAuthTag(tag)
        return Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]).toString('utf8')
    } catch {
        return null
    }
}

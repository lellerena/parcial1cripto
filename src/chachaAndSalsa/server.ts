import express from 'express'
import http from 'http'
import { Server } from 'socket.io'
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import crypto from 'crypto'
import {
    decryptMessageChaCha20,
    decryptMessageSalsa20,
    encryptMessageChaCha20,
    encryptMessageSalsa20
} from '../crypto/stream-cipher'
import { GoogleGenerativeAI } from '@google/generative-ai'

const app = express()
const server = http.createServer(app)
const io = new Server(server, {
    cors: {
        origin: '*'
    }
})

// Access your API key as an environment variable (see "Set up your API key" above)
const genAI = new GoogleGenerativeAI('AIzaSyApScEEWXYebBFgMtKpfQuZ6V2ZhpHH0y8')

// The Gemini 1.5 models are versatile and work with most use cases
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' })

// Generar claves para ambos algoritmos
const salsa20Key = nacl.randomBytes(32)
const encodedSalsa20Key = naclUtil.encodeBase64(salsa20Key)

const chacha20Key = crypto.randomBytes(32)
const encodedChacha20Key = chacha20Key.toString('base64')

io.on('connection', (socket) => {
    console.log('Cliente conectado')
    let selectedAlgorithm: string | null = null
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

    // Manejar la selección del algoritmo
    socket.on('select_algorithm', (data) => {
        let { algorithm } = data
        selectedAlgorithm = algorithm
        console.log(`Cliente eligió algoritmo: ${algorithm}`)
        algorithm = algorithm.toLowerCase()

        // Enviar la clave correspondiente según el algoritmo seleccionado
        if (algorithm === 'salsa20') {
            console.log('Enviando clave Salsa20 al cliente')
            socket.emit('shared_key', {
                key: encodedSalsa20Key,
                algorithm: 'salsa20'
            })
        } else if (algorithm === 'chacha20') {
            console.log(
                'Enviando clave ChaCha20 al cliente',
                encodedChacha20Key
            )
            socket.emit('shared_key', {
                key: encodedChacha20Key,
                algorithm: 'chacha20'
            })
        } else {
            socket.emit('error', { message: 'Algoritmo no soportado' })
        }
    })

    // Manejar mensajes cifrados con Salsa20
    socket.on('salsa20_message', async (data) => {
        const { ciphertext, nonce } = data
        const decryptedMessage = decryptMessageSalsa20(
            naclUtil.decodeBase64(ciphertext),
            salsa20Key,
            naclUtil.decodeBase64(nonce)
        )

        console.log('Mensaje Salsa20 recibido (descifrado):', decryptedMessage)

        const result = await chat.sendMessage(decryptedMessage)
        const res = await result.response
        const randomResponse = res.text()

        // Enviar respuesta cifrada con Salsa20
        const response = `Servidor recibió mensaje Salsa20: "${decryptedMessage}"`
        const responseNonce = nacl.randomBytes(24)
        const encryptedResponse = encryptMessageSalsa20(
            response,
            salsa20Key,
            responseNonce
        )

        socket.emit('message', {
            text: naclUtil.encodeBase64(encryptedResponse),
            nonce: naclUtil.encodeBase64(responseNonce),
            encrypted: true,
            scenario: 1
        })

        const randomNonce = nacl.randomBytes(24)
        const encryptedRandomResponse = encryptMessageSalsa20(
            randomResponse,
            salsa20Key,
            randomNonce
        )

        socket.emit('message', {
            text: naclUtil.encodeBase64(encryptedRandomResponse),
            nonce: naclUtil.encodeBase64(randomNonce),
            encrypted: true,
            scenario: 1
        })
    })

    // Manejar mensajes cifrados con ChaCha20
    socket.on('chacha20_message', (data) => {
        const { ciphertextcha, nonce, tag } = data
        const decryptedMessage = decryptMessageChaCha20(
            Buffer.from(ciphertextcha, 'base64'),
            chacha20Key,
            Buffer.from(nonce, 'base64'),
            Buffer.from(tag, 'base64')
        )

        console.log('Mensaje ChaCha20 recibido (descifrado):', decryptedMessage)

        // Responder con un mensaje cifrado con ChaCha20
        const response = `Servidor recibió mensaje ChaCha20: "${decryptedMessage}"`
        const responseNonce = crypto.randomBytes(12)
        const { ciphertext: encryptedResponse, tag: responseTag } =
            encryptMessageChaCha20(response, chacha20Key, responseNonce)

        socket.emit('chacha20_response', {
            ciphertext: encryptedResponse.toString('base64'),
            nonce: responseNonce.toString('base64'),
            tag: responseTag.toString('base64')
        })
    })

    socket.on('disconnect', () => {
        console.log('Cliente desconectado')
    })
})

server.listen(3000, () => {
    console.log('Servidor escuchando en el puerto 3000')
})

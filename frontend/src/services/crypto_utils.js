import { invoke } from '@tauri-apps/api/core';
import { v4 as uuidv4 } from 'uuid';

/**
 * Clase de utilidades criptográficas que utiliza las funciones de Tauri
 * para realizar operaciones criptográficas en el frontend
 */
export class CryptoUtils {
    /**
     * Clase personalizada para errores criptográficos
     */
    static CryptoError = class extends Error {
        constructor(message, operation, originalError = null) {
            super(message);
            this.name = 'CryptoError';
            this.operation = operation;
            this.originalError = originalError;
        }
    };

    /**
     * Genera un par de claves RSA
     * @returns {Promise<{publicKey: string, privateKey: string}>}
     */
    async generateRsaKeys() {
        try {
            const [publicKey, privateKey] = await invoke('generate_rsa_keys');
            return { publicKey, privateKey };
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al generar claves RSA',
                'generate_rsa_keys',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Genera un par de claves Diffie-Hellman
     * @returns {Promise<{publicKey: string, privateKey: string}>}
     */
    async generateDhKeys() {
        try {
            const [publicKey, privateKey] = await invoke('generate_dh_keys');
            return { publicKey, privateKey };
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al generar claves DH',
                'generate_dh_keys',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Genera un par de claves Diffie-Hellman efímeras para una sesión
     * @returns {Promise<{publicKey: string, privateKey: string}>}
     */
    async generateEphemeralDhKeys() {
        return this.generateDhKeys();
    }

    /**
     * Firma datos usando una clave privada RSA
     * @param {string} data - Datos a firmar
     * @param {string} privateKeyPem - Clave privada RSA en formato PEM
     * @returns {Promise<string>} - Firma en formato Base64
     */
    async signData(data, privateKeyPem) {
        try {
            return await invoke('sign_data', { data, privateKeyPem });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al firmar datos',
                'sign_data',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Verifica una firma usando una clave pública RSA
     * @param {string} data - Datos originales
     * @param {string} signatureBase64 - Firma en formato Base64
     * @param {string} publicKeyPem - Clave pública RSA en formato PEM
     * @returns {Promise<boolean>} - true si la firma es válida
     */
    async verifySignature(data, signatureBase64, publicKeyPem) {
        try {
            return await invoke('verify_signature', { data, signatureBase64, publicKeyPem });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al verificar firma',
                'verify_signature',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Genera un secreto compartido usando claves Diffie-Hellman
     * @param {string} privateKeyB64 - Clave privada DH en formato Base64
     * @param {string} publicKeyB64 - Clave pública DH en formato Base64
     * @returns {Promise<string>} - Secreto compartido en formato Base64
     */
    async generateSharedSecret(privateKeyB64, publicKeyB64) {
        try {
            return await invoke('generate_shared_secret', { privateKeyB64, publicKeyB64 });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al generar secreto compartido',
                'generate_shared_secret',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Cifra un mensaje usando AES
     * @param {string} message - Mensaje a cifrar
     * @param {string} keyB64 - Clave en formato Base64
     * @returns {Promise<string>} - Mensaje cifrado en formato Base64
     */
    async encryptMessage(message, keyB64) {
        try {
            return await invoke('encrypt_message_aes', { message, keyB64 });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al cifrar mensaje',
                'encrypt_message_aes',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Descifra un mensaje usando AES
     * @param {string} encryptedB64 - Mensaje cifrado en formato Base64
     * @param {string} keyB64 - Clave en formato Base64
     * @returns {Promise<string>} - Mensaje descifrado
     */
    async decryptMessage(encryptedB64, keyB64) {
        try {
            return await invoke('decrypt_message_aes', { encryptedB64, keyB64 });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al descifrar mensaje',
                'decrypt_message_aes',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Hashea una contraseña usando Argon2
     * @param {string} password - Contraseña a hashear
     * @returns {Promise<string>} - Hash de la contraseña
     */
    async hashPassword(password) {
        try {
            return await invoke('hash_password', { password });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al hashear contraseña',
                'hash_password',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Verifica una contraseña contra su hash
     * @param {string} password - Contraseña a verificar
     * @param {string} passwordHash - Hash de la contraseña
     * @returns {Promise<boolean>} - true si la contraseña es correcta
     */
    async verifyPassword(password, passwordHash) {
        try {
            return await invoke('verify_password', { password, passwordHash });
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al verificar contraseña',
                'verify_password',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Genera un identificador único para una sesión
     * @returns {string} - Identificador único
     */
    generateSessionId() {
        return uuidv4();
    }

    /**
     * Genera un nonce único para un mensaje
     * @returns {string} - Nonce único
     */
    generateMessageNonce() {
        return uuidv4();
    }

    /**
     * Cifra y firma un mensaje para una sesión con protección contra replay attacks
     * @param {string} message - Mensaje a cifrar
     * @param {string} messageKey - Clave de mensaje en formato Base64
     * @param {string} rsaPrivateKey - Clave RSA privada para firmar
     * @returns {Promise<string>} - JSON con mensaje cifrado y firma
     */
    async encryptAndSignMessage(message, messageKey, rsaPrivateKey) {
        try {
            // Generar nonce único
            const nonce = this.generateMessageNonce();

            // Crear objeto de mensaje con timestamp y nonce
            const messageData = {
                content: message,
                timestamp: new Date().toISOString(),
                nonce: nonce,
                message_version: 1 // Para futuras actualizaciones del formato
            };

            // Convertir a JSON y cifrar
            const messageJson = JSON.stringify(messageData);
            const encryptedMessage = await this.encryptMessage(messageJson, messageKey);

            // Firmar el mensaje cifrado
            const signature = await this.signData(encryptedMessage, rsaPrivateKey);

            // Crear objeto JSON con mensaje cifrado y firma
            const messageObject = {
                encrypted_content: encryptedMessage,
                signature: signature,
                timestamp: new Date().toISOString()
            };

            return JSON.stringify(messageObject);
        } catch (error) {
            const cryptoError = new CryptoUtils.CryptoError(
                'Error al cifrar y firmar mensaje',
                'encrypt_and_sign_message',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }

    /**
     * Verifica y descifra un mensaje de una sesión con protección contra replay attacks
     * @param {string} encryptedMessageJson - JSON con mensaje cifrado y firma
     * @param {string} messageKey - Clave de mensaje en formato Base64
     * @param {string} rsaPublicKey - Clave RSA pública del remitente
     * @param {Set} processedNonces - Conjunto de nonces ya procesados
     * @returns {Promise<Object>} - Objeto con mensaje descifrado y metadatos
     */
    async verifyAndDecryptMessage(encryptedMessageJson, messageKey, rsaPublicKey, processedNonces = null) {
        try {
            // Parsear el JSON
            const messageObject = JSON.parse(encryptedMessageJson);

            // Verificar la firma
            const isValid = await this.verifySignature(
                messageObject.encrypted_content,
                messageObject.signature,
                rsaPublicKey
            );

            if (!isValid) {
                throw new CryptoUtils.CryptoError(
                    'La firma del mensaje no es válida',
                    'verify_signature',
                    null
                );
            }

            // Descifrar el mensaje
            const decryptedJson = await this.decryptMessage(messageObject.encrypted_content, messageKey);
            const messageData = JSON.parse(decryptedJson);

            // Verificar nonce si se proporciona un conjunto de nonces procesados
            if (processedNonces && messageData.nonce) {
                if (processedNonces.has(messageData.nonce)) {
                    return {
                        content: null,
                        error: 'replay_attack',
                        errorMessage: 'Mensaje repetido detectado (nonce duplicado)',
                        metadata: {
                            timestamp: messageData.timestamp,
                            nonce: messageData.nonce,
                            version: messageData.message_version
                        }
                    };
                }

                // Registrar el nonce como procesado
                processedNonces.add(messageData.nonce);
            }

            // Verificar timestamp (opcional, para mensajes muy antiguos)
            if (messageData.timestamp) {
                const msgTime = new Date(messageData.timestamp);
                const now = new Date();
                const timeDiff = now - msgTime;

                // Si el mensaje tiene más de 24 horas, marcarlo como potencialmente sospechoso
                if (timeDiff > 86400000) {
                    return {
                        content: messageData.content,
                        warning: 'message_old',
                        warningMessage: 'Mensaje antiguo (más de 24 horas)',
                        metadata: {
                            timestamp: messageData.timestamp,
                            nonce: messageData.nonce,
                            version: messageData.message_version,
                            age: Math.floor(timeDiff / 3600000) // Edad en horas
                        }
                    };
                }
            }

            // Mensaje válido
            return {
                content: messageData.content,
                metadata: {
                    timestamp: messageData.timestamp,
                    nonce: messageData.nonce,
                    version: messageData.message_version
                }
            };
        } catch (error) {
            // Capturar y reenviar errores específicos de CryptoError
            if (error instanceof CryptoUtils.CryptoError) {
                throw error;
            }

            // Otros errores
            const cryptoError = new CryptoUtils.CryptoError(
                `Error al verificar y descifrar mensaje: ${error.message}`,
                'verify_and_decrypt_message',
                error
            );
            console.error(cryptoError);
            throw cryptoError;
        }
    }
}

export default CryptoUtils;

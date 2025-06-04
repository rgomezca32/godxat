import { KeyStorage } from './key_storage';
import { CryptoUtils } from './crypto_utils';

/**
 * Clase para gestionar sesiones de chat cifradas
 */
export class SessionManager {
    constructor() {
        this.keyStorage = new KeyStorage();
        this.cryptoUtils = new CryptoUtils();
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
    }

    /**
     * Inicializa una nueva sesión
     * @param {string} sessionId - ID de la sesión
     * @param {string} role - Rol en la sesión ('initiator' o 'receiver')
     * @returns {Promise<{ephemeralPublic: string, ephemeralPrivate: string, signature: string}>}
     */
    async initializeSession(sessionId, role) {
        try {
            if (!this.currentUser) {
                throw new Error('No hay usuario activo');
            }

            // Generar claves DH efímeras
            const { publicKey: ephemeralPublic, privateKey: ephemeralPrivate } =
                await this.cryptoUtils.generateEphemeralDhKeys();

            // Cargar clave RSA privada para firmar
            const { rsaPrivate } = await this.keyStorage.loadPrivateKeys(this.currentUser.username);

            // Firmar la clave DH pública efímera
            const signature = await this.cryptoUtils.signData(ephemeralPublic, rsaPrivate);

            // Almacenar clave privada efímera localmente
            await this.keyStorage.storeEphemeralKeys(
                this.currentUser.username,
                sessionId,
                role,
                ephemeralPrivate
            );

            return { ephemeralPublic, ephemeralPrivate, signature };
        } catch (error) {
            console.error('Error al inicializar sesión:', error);
            throw error;
        }
    }

    /**
     * Completa una sesión con la clave pública del otro usuario
     * @param {string} sessionId - ID de la sesión
     * @param {string} peerEphemeralPublic - Clave DH pública efímera del otro usuario
     * @param {string} peerSignature - Firma de la clave DH pública del otro usuario
     * @param {string} peerRsaPublic - Clave RSA pública del otro usuario
     * @returns {Promise<string>} - Secreto compartido
     */
    async completeSession(sessionId, peerEphemeralPublic, peerSignature, peerRsaPublic) {
        try {
            if (!this.currentUser) {
                throw new Error('No hay usuario activo');
            }

            // Verificar la firma de la clave DH pública del otro usuario
            const isValid = await this.cryptoUtils.verifySignature(
                peerEphemeralPublic,
                peerSignature,
                peerRsaPublic
            );

            if (!isValid) {
                throw new Error('La firma de la clave DH pública no es válida');
            }

            // Cargar clave privada efímera
            const { ephemeralPrivate, role } = await this.keyStorage.loadEphemeralKeys(
                this.currentUser.username,
                sessionId
            );

            // Almacenar clave pública efímera del otro usuario
            await this.keyStorage.storeEphemeralKeys(
                this.currentUser.username,
                sessionId,
                role,
                ephemeralPrivate,
                peerEphemeralPublic,
                peerSignature,
                peerRsaPublic
            );

            // Calcular secreto compartido
            const sharedSecret = await this.cryptoUtils.generateSharedSecret(
                ephemeralPrivate,
                peerEphemeralPublic
            );

            // Almacenar secreto compartido y derivar claves
            await this.keyStorage.storeSharedSecret(
                this.currentUser.username,
                sessionId,
                sharedSecret
            );

            return sharedSecret;
        } catch (error) {
            console.error('Error al completar sesión:', error);
            throw error;
        }
    }

    /**
     * Deriva una clave de mensaje para cifrar/descifrar
     * @param {string} sessionId - ID de la sesión
     * @param {number} messageNumber - Número de mensaje
     * @returns {Promise<string>} - Clave de mensaje
     */
    async deriveMessageKey(sessionId, messageNumber) {
        try {
            if (!this.currentUser) {
                throw new Error('No hay usuario activo');
            }

            return await this.keyStorage.deriveMessageKey(
                this.currentUser.username,
                sessionId,
                messageNumber
            );
        } catch (error) {
            console.error('Error al derivar clave de mensaje:', error);
            throw error;
        }
    }

    /**
     * Cifra y firma un mensaje
     * @param {string} message - Mensaje a cifrar
     * @param {string} messageKey - Clave de mensaje
     * @returns {Promise<string>} - Mensaje cifrado y firmado en formato JSON
     */
    async encryptAndSignMessage(message, messageKey) {
        try {
            if (!this.currentUser) {
                throw new Error('No hay usuario activo');
            }

            // Cargar clave RSA privada para firmar
            const { rsaPrivate } = await this.keyStorage.loadPrivateKeys(this.currentUser.username);

            // Cifrar y firmar el mensaje
            return await this.cryptoUtils.encryptAndSignMessage(
                message,
                messageKey,
                rsaPrivate
            );
        } catch (error) {
            console.error('Error al cifrar y firmar mensaje:', error);
            throw error;
        }
    }

    /**
     * Verifica y descifra un mensaje
     * @param {string} encryptedMessageJson - Mensaje cifrado y firmado en formato JSON
     * @param {string} messageKey - Clave de mensaje
     * @param {string} senderRsaPublic - Clave RSA pública del remitente
     * @returns {Promise<string>} - Mensaje descifrado
     */
    async verifyAndDecryptMessage(encryptedMessageJson, messageKey, senderRsaPublic) {
        try {
            return await this.cryptoUtils.verifyAndDecryptMessage(
                encryptedMessageJson,
                messageKey,
                senderRsaPublic
            );
        } catch (error) {
            console.error('Error al verificar y descifrar mensaje:', error);
            throw error;
        }
    }
}

export default SessionManager;

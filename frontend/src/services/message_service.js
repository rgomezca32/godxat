import axios from 'axios';
import { KeyStorage } from './key_storage';
import { CryptoUtils } from './crypto_utils';

/**
 * Servicio de mensajería que maneja el envío y recepción de mensajes cifrados
 * utilizando criptografía en el frontend con Tauri
 */
export class MessageService {
    constructor() {
        this.apiUrl = 'https://godxat-api.onrender.com';
        this.keyStorage = new KeyStorage();
        this.cryptoUtils = new CryptoUtils();
        this.token = null;
        this.currentUser = null;
        this.processedNonces = new Set(); // Para protección contra replay attacks
        this.pollingIntervals = {}; // Para sincronización en tiempo real
        this.DEFAULT_POLLING_INTERVAL = 3000; // 3 segundos
    }

    /**
     * Envía un mensaje cifrado a través de una sesión
     * @param {string} sessionId - ID de la sesión
     * @param {string} message - Mensaje a enviar
     * @returns {Promise<Object>} - Respuesta del servidor
     */
    async sendMessage(sessionId, message) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            // Obtener el último número de mensaje para esta sesión
            const messages = await this.getMessages(sessionId);
            const lastMessage = messages.messages[messages.messages.length - 1];
            const messageNumber = lastMessage ? lastMessage.message_number + 1 : 1;

            // Cargar clave RSA privada para firmar
            const { rsaPrivate } = await this.keyStorage.loadPrivateKeys(this.currentUser.username);

            // Derivar clave de mensaje
            const messageKey = await this.keyStorage.deriveMessageKey(
                this.currentUser.username,
                sessionId,
                messageNumber
            );

            // Cifrar y firmar el mensaje con protección contra replay attacks
            const encryptedMessageJson = await this.cryptoUtils.encryptAndSignMessage(
                message,
                messageKey,
                rsaPrivate
            );

            // Enviar mensaje cifrado al servidor
            const response = await axios.post(
                `${this.apiUrl}/send_message_ephemeral/`,
                {
                    session_id: sessionId,
                    message: encryptedMessageJson
                },
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error al enviar mensaje:', error);
            throw error;
        }
    }

    /**
     * Obtiene y descifra mensajes de una sesión
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Mensajes descifrados
     */
    async getMessages(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            // Obtener mensajes cifrados del servidor
            const response = await axios.get(
                `${this.apiUrl}/get_messages_ephemeral/${sessionId}`,
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            // Descifrar mensajes
            const decryptedMessages = [];
            for (const msg of response.data.messages) {
                try {
                    // Obtener información del remitente
                    const sender = await axios.get(
                        `${this.apiUrl}/get_user/${msg.sender_id}`,
                        {
                            headers: {
                                'Authorization': `Bearer ${this.token}`
                            }
                        }
                    );

                    // Derivar clave de mensaje
                    const messageKey = await this.keyStorage.deriveMessageKey(
                        this.currentUser.username,
                        sessionId,
                        msg.message_number
                    );

                    // Verificar y descifrar el mensaje con protección contra replay attacks
                    const result = await this.cryptoUtils.verifyAndDecryptMessage(
                        msg.encrypted_message,
                        messageKey,
                        sender.data.rsa_public_key,
                        this.processedNonces
                    );

                    // Manejar diferentes resultados según el estado de verificación
                    if (result.error) {
                        decryptedMessages.push({
                            ...msg,
                            message: `[Error: ${result.errorMessage}]`,
                            error: result.error,
                            metadata: result.metadata
                        });
                    } else if (result.warning) {
                        decryptedMessages.push({
                            ...msg,
                            message: result.content,
                            warning: result.warning,
                            warningMessage: result.warningMessage,
                            metadata: result.metadata
                        });
                    } else {
                        decryptedMessages.push({
                            ...msg,
                            message: result.content,
                            metadata: result.metadata
                        });
                    }
                } catch (error) {
                    // Si hay error al descifrar, mantener el mensaje con error
                    decryptedMessages.push({
                        ...msg,
                        message: `[Error al descifrar: ${error.message}]`,
                        error: error.message
                    });
                }
            }

            return { messages: decryptedMessages };
        } catch (error) {
            console.error('Error al obtener mensajes:', error);
            throw error;
        }
    }

    /**
     * Obtiene las conversaciones activas del usuario
     * @returns {Promise<Object>} - Lista de conversaciones
     */
    async getConversations() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/get_conversations_ephemeral/`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener conversaciones:', error);
            throw error;
        }
    }

    /**
     * Inicia la sincronización en tiempo real de mensajes para una sesión
     * @param {string} sessionId - ID de la sesión
     * @param {Function} callback - Función a llamar cuando hay nuevos mensajes
     * @returns {boolean} - true si se inició correctamente
     */
    startMessagePolling(sessionId, callback) {
        // Detener polling existente si lo hay
        this.stopMessagePolling(sessionId);

        // Iniciar nuevo polling
        this.pollingIntervals[sessionId] = setInterval(async () => {
            try {
                const messages = await this.getMessages(sessionId);
                callback(messages);
            } catch (error) {
                console.error('Error en polling de mensajes:', error);
            }
        }, this.DEFAULT_POLLING_INTERVAL);

        return true;
    }

    /**
     * Detiene la sincronización en tiempo real de mensajes para una sesión
     * @param {string} sessionId - ID de la sesión
     */
    stopMessagePolling(sessionId) {
        if (this.pollingIntervals[sessionId]) {
            clearInterval(this.pollingIntervals[sessionId]);
            delete this.pollingIntervals[sessionId];
        }
    }

    /**
     * Detiene todas las sincronizaciones en tiempo real
     */
    stopAllPolling() {
        Object.keys(this.pollingIntervals).forEach(sessionId => {
            this.stopMessagePolling(sessionId);
        });
    }

    /**
     * Limpia los recursos al cerrar sesión
     */
    logout() {
        // Detener todos los pollings
        this.stopAllPolling();

        // Limpiar datos de sesión
        this.token = null;
        this.currentUser = null;
        this.processedNonces.clear();
    }

    initMessageService(){
        this.token = localStorage.getItem('token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
    }
}

export default new MessageService();

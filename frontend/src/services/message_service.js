// message_service.js modificado
import axios from 'axios';
import { KeyStorage } from './key_storage';
import { CryptoUtils } from './crypto_utils';
import WebSocketService from './websocket_service';

/**
 * Servicio de mensajería que maneja el envío y recepción de mensajes cifrados
 * utilizando criptografía en el frontend con Tauri y WebSockets para tiempo real
 */
export class MessageService {
    constructor() {
        this.apiUrl = process.env.VUE_APP_API_URL;
        this.keyStorage = new KeyStorage();
        this.cryptoUtils = new CryptoUtils();
        this.token = null;
        this.currentUser = null;
        this.processedNonces = new Set(); // Para protección contra replay attacks
        this.messageCallbacks = new Map(); // Para callbacks de mensajes
        this.messageListeners = new Map(); // Para listeners de mensajes por sesión
        this.typingDebounceTimers = new Map(); // Para debounce de notificaciones de escritura
    }

    /**
     * Inicializa el servicio de mensajes
     */
    initMessageService() {
        this.token = localStorage.getItem('token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

        // Registrar manejadores de eventos WebSocket
        this.registerWebSocketHandlers();
    }

    /**
     * Registra manejadores para eventos WebSocket
     */
    registerWebSocketHandlers() {
        // Manejar nuevos mensajes
        WebSocketService.on('new_message', this.handleNewMessage.bind(this));

        // Manejar confirmaciones de entrega
        WebSocketService.on('message_delivered', this.handleMessageDelivered.bind(this));

        // Manejar confirmaciones de lectura
        WebSocketService.on('message_read', this.handleMessageRead.bind(this));
    }

    /**
     * Maneja la notificación de nuevo mensaje
     * @param {object} data - Datos del mensaje
     */
    async handleNewMessage(data) {
        try {
            // Verificar si el mensaje es para el usuario actual
            if (data.receiver_id !== this.currentUser.id) {
                return;
            }

            // Obtener el mensaje completo
            const messages = await this.getMessages(data.session_id);

            // Notificar entrega
            WebSocketService.notifyMessageDelivered(data.message_id, data.session_id);

            // Llamar a los callbacks registrados para esta sesión
            if (this.messageListeners.has(data.session_id)) {
                const listeners = this.messageListeners.get(data.session_id);
                listeners.forEach(callback => {
                    try {
                        callback(messages);
                    } catch (error) {
                        console.error('Error en callback de mensaje:', error);
                    }
                });
            }
        } catch (error) {
            console.error('Error al manejar nuevo mensaje:', error);
        }
    }

    /**
     * Maneja la confirmación de entrega de mensaje
     * @param {object} data - Datos de la confirmación
     */
    handleMessageDelivered(data) {
        // Llamar a los callbacks registrados para este mensaje
        if (this.messageCallbacks.has(`delivered_${data.message_id}`)) {
            const callbacks = this.messageCallbacks.get(`delivered_${data.message_id}`);
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error en callback de entrega:', error);
                }
            });

            // Limpiar callbacks
            this.messageCallbacks.delete(`delivered_${data.message_id}`);
        }
    }

    /**
     * Maneja la confirmación de lectura de mensaje
     * @param {object} data - Datos de la confirmación
     */
    handleMessageRead(data) {
        // Llamar a los callbacks registrados para este mensaje
        if (this.messageCallbacks.has(`read_${data.message_id}`)) {
            const callbacks = this.messageCallbacks.get(`read_${data.message_id}`);
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error en callback de lectura:', error);
                }
            });

            // Limpiar callbacks
            this.messageCallbacks.delete(`read_${data.message_id}`);
        }
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

                    // Verificar y descifrar el mensaje
                    const result = await this.cryptoUtils.verifyAndDecryptMessage(
                        msg.encrypted_message,
                        messageKey,
                        sender.data.rsa_public_key
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

                    // Notificar lectura del mensaje si no es del usuario actual
                    if (msg.sender_id !== this.currentUser.id) {
                        WebSocketService.notifyMessageRead(msg.id, sessionId);
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
     * Registra un listener para mensajes de una sesión específica
     * @param {string} sessionId - ID de la sesión
     * @param {Function} callback - Función a llamar cuando hay nuevos mensajes
     * @returns {Function} - Función para eliminar el listener
     */
    listenForMessages(sessionId, callback) {
        if (!this.messageListeners.has(sessionId)) {
            this.messageListeners.set(sessionId, new Set());
        }

        this.messageListeners.get(sessionId).add(callback);

        // Devolver función para eliminar el listener
        return () => {
            if (this.messageListeners.has(sessionId)) {
                this.messageListeners.get(sessionId).delete(callback);
                if (this.messageListeners.get(sessionId).size === 0) {
                    this.messageListeners.delete(sessionId);
                }
            }
        };
    }

    /**
     * Notifica que el usuario está escribiendo en una sesión
     * @param {string} sessionId - ID de la sesión
     */
    notifyTyping(sessionId) {
        // Debounce para evitar enviar demasiadas notificaciones
        if (this.typingDebounceTimers.has(sessionId)) {
            clearTimeout(this.typingDebounceTimers.get(sessionId));
        }

        this.typingDebounceTimers.set(sessionId, setTimeout(() => {
            WebSocketService.notifyTyping(sessionId);
            this.typingDebounceTimers.delete(sessionId);
        }, 500)); // 500ms de debounce
    }

    /**
     * Verifica si un usuario está escribiendo en una sesión
     * @param {string} sessionId - ID de la sesión
     * @returns {boolean} - true si el usuario está escribiendo
     */
    isUserTyping(sessionId) {
        return WebSocketService.isUserTyping(sessionId);
    }

    /**
     * Verifica si un usuario está en línea
     * @param {number} userId - ID del usuario
     * @returns {boolean} - true si el usuario está en línea
     */
    isUserOnline(userId) {
        return WebSocketService.isUserOnline(userId);
    }

    /**
     * Limpia los recursos al cerrar sesión
     */
    logout() {
        // Limpiar datos de sesión
        this.token = null;
        this.currentUser = null;
        this.processedNonces.clear();
        this.messageCallbacks.clear();
        this.messageListeners.clear();

        // Limpiar timers de debounce
        this.typingDebounceTimers.forEach(timer => clearTimeout(timer));
        this.typingDebounceTimers.clear();

        // Eliminar manejadores de eventos WebSocket
        WebSocketService.off('new_message');
        WebSocketService.off('message_delivered');
        WebSocketService.off('message_read');
    }
}

export default new MessageService();


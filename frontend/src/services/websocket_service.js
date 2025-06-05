// websocket_service.js
import { ref, reactive } from 'vue';

/**
 * Servicio para manejar conexiones WebSocket y eventos en tiempo real
 */
export class WebSocketService {
    constructor() {
        this.apiUrl = process.env.VUE_APP_API_URL || '';
        this.wsUrl = this.apiUrl.replace(/^http/, 'ws') + '/ws';
        this.socket = null;
        this.token = null;
        this.currentUser = null;
        this.isConnected = ref(false);
        this.isConnecting = ref(false);
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // ms
        this.pingInterval = null;
        this.eventHandlers = {};
        this.pendingMessages = [];
        this.onlineUsers = reactive(new Set());
        this.typingUsers = reactive(new Map()); // Map de session_id -> {user_id, timestamp}
    }

    /**
     * Inicializa el servicio WebSocket
     */
    init() {
        this.token = localStorage.getItem('token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

        if (this.token && this.currentUser) {
            this.connect();
        }
    }

    /**
     * Establece la conexión WebSocket
     */
    connect() {
        if (this.isConnecting.value || this.isConnected.value || !this.token) {
            return;
        }

        this.isConnecting.value = true;

        try {
            // Cerrar socket existente si lo hay
            if (this.socket) {
                this.socket.close();
            }

            // Crear nuevo socket
            this.socket = new WebSocket(this.wsUrl);

            // Configurar eventos
            this.socket.onopen = this.handleOpen.bind(this);
            this.socket.onmessage = this.handleMessage.bind(this);
            this.socket.onclose = this.handleClose.bind(this);
            this.socket.onerror = this.handleError.bind(this);
        } catch (error) {
            console.error('Error al conectar WebSocket:', error);
            this.isConnecting.value = false;
            this.scheduleReconnect();
        }
    }

    /**
     * Maneja el evento de apertura de conexión
     */
    handleOpen() {
        console.log('WebSocket conectado');
        this.isConnected.value = true;
        this.isConnecting.value = false;
        this.reconnectAttempts = 0;

        // Enviar autenticación
        this.sendEvent('auth', { token: this.token });

        // Configurar ping periódico
        this.startPingInterval();

        // Enviar mensajes pendientes
        this.sendPendingMessages();
    }

    /**
     * Maneja los mensajes recibidos
     * @param {MessageEvent} event - Evento de mensaje
     */
    handleMessage(event) {
        try {
            const message = JSON.parse(event.data);
            const eventType = message.event;
            const data = message.data;

            console.log('WebSocket mensaje recibido:', eventType, data);

            // Procesar eventos específicos
            switch (eventType) {
                case 'pong':
                    // No hacer nada, solo confirmar que la conexión está viva
                    break;

                case 'auth_success':
                    console.log('Autenticación WebSocket exitosa');
                    break;

                case 'user_online':
                    this.onlineUsers.add(data.user_id);
                    break;

                case 'user_offline':
                    this.onlineUsers.delete(data.user_id);
                    break;

                case 'user_typing':
                    this.typingUsers.set(data.session_id, {
                        user_id: data.user_id,
                        timestamp: Date.now()
                    });

                    // Limpiar estado de escritura después de 3 segundos
                    setTimeout(() => {
                        const typingInfo = this.typingUsers.get(data.session_id);
                        if (typingInfo && typingInfo.user_id === data.user_id && Date.now() - typingInfo.timestamp > 3000) {
                            this.typingUsers.delete(data.session_id);
                        }
                    }, 3000);
                    break;

                default:
                    // Llamar a los manejadores registrados para este tipo de evento
                    if (this.eventHandlers[eventType]) {
                        this.eventHandlers[eventType].forEach(handler => {
                            try {
                                handler(data);
                            } catch (handlerError) {
                                console.error(`Error en manejador de evento ${eventType}:`, handlerError);
                            }
                        });
                    }
                    break;
            }
        } catch (error) {
            console.error('Error al procesar mensaje WebSocket:', error);
        }
    }

    /**
     * Maneja el cierre de conexión
     * @param {CloseEvent} event - Evento de cierre
     */
    handleClose(event) {
        console.log('WebSocket desconectado:', event.code, event.reason);
        this.isConnected.value = false;
        this.isConnecting.value = false;

        // Limpiar ping interval
        this.stopPingInterval();

        // Intentar reconectar si no fue un cierre normal
        if (event.code !== 1000) {
            this.scheduleReconnect();
        }
    }

    /**
     * Maneja errores de conexión
     * @param {Event} error - Evento de error
     */
    handleError(error) {
        console.error('Error en WebSocket:', error);
        // No hacer nada aquí, el evento onclose se disparará después
    }

    /**
     * Programa un intento de reconexión
     */
    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Máximo número de intentos de reconexión alcanzado');
            return;
        }

        // Calcular delay con backoff exponencial
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts);
        this.reconnectAttempts++;

        console.log(`Intentando reconectar en ${delay}ms (intento ${this.reconnectAttempts})`);

        setTimeout(() => {
            if (!this.isConnected.value && !this.isConnecting.value) {
                this.connect();
            }
        }, delay);
    }

    /**
     * Inicia el intervalo de ping
     */
    startPingInterval() {
        this.stopPingInterval();
        this.pingInterval = setInterval(() => {
            if (this.isConnected.value) {
                this.sendEvent('ping', {});
            }
        }, 30000); // 30 segundos
    }

    /**
     * Detiene el intervalo de ping
     */
    stopPingInterval() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    /**
     * Envía un evento al servidor
     * @param {string} eventType - Tipo de evento
     * @param {object} data - Datos del evento
     */
    sendEvent(eventType, data) {
        const message = {
            event: eventType,
            data: data,
            timestamp: new Date().toISOString()
        };

        if (this.isConnected.value && this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify(message));
            return true;
        } else {
            // Guardar mensaje para enviar cuando se conecte
            if (eventType !== 'ping') { // No guardar pings
                this.pendingMessages.push(message);
            }

            // Intentar conectar si no está conectado
            if (!this.isConnected.value && !this.isConnecting.value) {
                this.connect();
            }

            return false;
        }
    }

    /**
     * Envía los mensajes pendientes
     */
    sendPendingMessages() {
        if (!this.isConnected.value || !this.socket) {
            return;
        }

        const messages = [...this.pendingMessages];
        this.pendingMessages = [];

        for (const message of messages) {
            try {
                this.socket.send(JSON.stringify(message));
            } catch (error) {
                console.error('Error al enviar mensaje pendiente:', error);
                this.pendingMessages.push(message);
            }
        }
    }

    /**
     * Registra un manejador para un tipo de evento
     * @param {string} eventType - Tipo de evento
     * @param {Function} handler - Función manejadora
     * @returns {Function} - Función para eliminar el manejador
     */
    on(eventType, handler) {
        if (!this.eventHandlers[eventType]) {
            this.eventHandlers[eventType] = [];
        }

        this.eventHandlers[eventType].push(handler);

        // Devolver función para eliminar el manejador
        return () => {
            if (this.eventHandlers[eventType]) {
                this.eventHandlers[eventType] = this.eventHandlers[eventType].filter(h => h !== handler);
            }
        };
    }

    /**
     * Elimina todos los manejadores para un tipo de evento
     * @param {string} eventType - Tipo de evento
     */
    off(eventType) {
        if (eventType) {
            delete this.eventHandlers[eventType];
        } else {
            this.eventHandlers = {};
        }
    }

    /**
     * Notifica que el usuario está escribiendo en una sesión
     * @param {string} sessionId - ID de la sesión
     */
    notifyTyping(sessionId) {
        this.sendEvent('user_typing', { session_id: sessionId });
    }

    /**
     * Verifica si un usuario está en línea
     * @param {number} userId - ID del usuario
     * @returns {boolean} - true si el usuario está en línea
     */
    isUserOnline(userId) {
        return this.onlineUsers.has(userId);
    }

    /**
     * Verifica si un usuario está escribiendo en una sesión
     * @param {string} sessionId - ID de la sesión
     * @returns {boolean} - true si el usuario está escribiendo
     */
    isUserTyping(sessionId) {
        if (!this.typingUsers.has(sessionId)) {
            return false;
        }

        const typingInfo = this.typingUsers.get(sessionId);
        return Date.now() - typingInfo.timestamp < 3000; // 3 segundos
    }

    /**
     * Notifica que un mensaje ha sido entregado
     * @param {number} messageId - ID del mensaje
     * @param {string} sessionId - ID de la sesión
     */
    notifyMessageDelivered(messageId, sessionId) {
        this.sendEvent('message_delivered', { message_id: messageId, session_id: sessionId });
    }

    /**
     * Notifica que un mensaje ha sido leído
     * @param {number} messageId - ID del mensaje
     * @param {string} sessionId - ID de la sesión
     */
    notifyMessageRead(messageId, sessionId) {
        this.sendEvent('message_read', { message_id: messageId, session_id: sessionId });
    }

    /**
     * Cierra la conexión WebSocket
     */
    disconnect() {
        this.stopPingInterval();

        if (this.socket) {
            this.socket.close(1000, 'Cierre normal');
            this.socket = null;
        }

        this.isConnected.value = false;
        this.isConnecting.value = false;
        this.onlineUsers.clear();
        this.typingUsers.clear();
    }

    /**
     * Limpia los recursos al cerrar sesión
     */
    logout() {
        this.disconnect();
        this.token = null;
        this.currentUser = null;
        this.pendingMessages = [];
        this.eventHandlers = {};
    }
}

export default new WebSocketService();


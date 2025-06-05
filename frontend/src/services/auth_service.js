// auth_service.js corregido
import axios from 'axios';
import { KeyStorage } from './key_storage';
import { CryptoUtils } from './crypto_utils';
import WebSocketService from './websocket_service';

/**
 * Servicio de autenticación que maneja el registro, login y gestión de usuarios
 * utilizando criptografía en el frontend con Tauri y WebSockets para tiempo real
 */
export class AuthService {
    constructor() {
        this.apiUrl = process.env.VUE_APP_API_URL;
        this.keyStorage = new KeyStorage();
        this.cryptoUtils = new CryptoUtils();
        this.token = localStorage.getItem('token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
        this.sessionListeners = new Map(); // Para listeners de eventos de sesión
        this.sessionCompletionInProgress = new Set(); // Para evitar completar la misma sesión múltiples veces
    }

    /**
     * Inicializa el servicio de autenticación
     */
    init() {
        // Registrar manejadores de eventos WebSocket
        this.registerWebSocketHandlers();
    }

    /**
     * Registra manejadores para eventos WebSocket
     */
    registerWebSocketHandlers() {
        // Manejar solicitudes de sesión
        WebSocketService.on('session_request', this.handleSessionRequest.bind(this));

        // Manejar aceptaciones de sesión
        WebSocketService.on('session_accepted', this.handleSessionAccepted.bind(this));

        // Manejar rechazos de sesión
        WebSocketService.on('session_rejected', this.handleSessionRejected.bind(this));

        // Manejar completado de sesión
        WebSocketService.on('session_completed', this.handleSessionCompleted.bind(this));

        // Manejar confirmación de completado de sesión
        WebSocketService.on('session_completion_confirmed', this.handleSessionCompletionConfirmed.bind(this));

        // Manejar cierre de sesión
        WebSocketService.on('session_closed', this.handleSessionClosed.bind(this));

        // Manejar sesiones pendientes iniciales
        WebSocketService.on('pending_sessions', this.handlePendingSessions.bind(this));

        // Manejar sesiones incompletas iniciales
        WebSocketService.on('incomplete_sessions', this.handleIncompleteSessions.bind(this));
    }

    /**
     * Maneja la notificación de solicitud de sesión
     * @param {object} data - Datos de la solicitud
     */
    handleSessionRequest(data) {
        console.log('Solicitud de sesión recibida:', data);
        this.notifySessionListeners('session_request', data);
    }

    /**
     * Maneja la notificación de aceptación de sesión
     * @param {object} data - Datos de la aceptación
     */
    async handleSessionAccepted(data) {
        try {
            console.log('Sesión aceptada:', data);

            // Notificar a los listeners primero para actualizar la UI inmediatamente
            this.notifySessionListeners('session_accepted', data);

            // Evitar completar la misma sesión múltiples veces
            if (this.sessionCompletionInProgress.has(data.session_id)) {
                console.log(`Completado de sesión ${data.session_id} ya en progreso, ignorando duplicado`);
                return;
            }

            this.sessionCompletionInProgress.add(data.session_id);

            // Completar la sesión automáticamente
            try {
                await this.completeSession(data.session_id);
                console.log(`Sesión ${data.session_id} completada con éxito`);

                // Notificar a los listeners que la sesión ha sido completada
                this.notifySessionListeners('session_completion_confirmed', {
                    session_id: data.session_id,
                    receiver_id: data.receiver_id,
                    receiver_username: data.receiver_username,
                    updated_at: new Date().toISOString()
                });

                // Actualizar las sesiones activas
                await this.getActiveSessions();
            } catch (error) {
                console.error(`Error al completar sesión ${data.session_id}:`, error);
            } finally {
                // Eliminar de la lista de sesiones en progreso
                this.sessionCompletionInProgress.delete(data.session_id);
            }
        } catch (error) {
            console.error('Error al manejar aceptación de sesión:', error);
        }
    }

    /**
     * Maneja la notificación de rechazo de sesión
     * @param {object} data - Datos del rechazo
     */
    handleSessionRejected(data) {
        console.log('Sesión rechazada:', data);
        this.notifySessionListeners('session_rejected', data);
    }

    /**
     * Maneja la notificación de completado de sesión
     * @param {object} data - Datos del completado
     */
    async handleSessionCompleted(data) {
        console.log('Sesión completada:', data);
        this.notifySessionListeners('session_completed', data);

        // Actualizar las sesiones activas
        await this.getActiveSessions();
    }

    /**
     * Maneja la confirmación de completado de sesión
     * @param {object} data - Datos de la confirmación
     */
    async handleSessionCompletionConfirmed(data) {
        console.log('Confirmación de sesión completada:', data);
        this.notifySessionListeners('session_completion_confirmed', data);

        // Actualizar las sesiones activas
        await this.getActiveSessions();
    }

    /**
     * Maneja la notificación de cierre de sesión
     * @param {object} data - Datos del cierre
     */
    handleSessionClosed(data) {
        console.log('Sesión cerrada:', data);
        this.notifySessionListeners('session_closed', data);
    }

    /**
     * Maneja la notificación inicial de sesiones pendientes
     * @param {object} data - Datos de sesiones pendientes
     */
    handlePendingSessions(data) {
        console.log('Sesiones pendientes recibidas:', data);
        this.notifySessionListeners('pending_sessions', data);
    }

    /**
     * Maneja la notificación inicial de sesiones incompletas
     * @param {object} data - Datos de sesiones incompletas
     */
    handleIncompleteSessions(data) {
        console.log('Sesiones incompletas recibidas:', data);
        this.notifySessionListeners('incomplete_sessions', data);

        // Intentar completar sesiones incompletas automáticamente
        if (data.sessions && Array.isArray(data.sessions)) {
            this.processIncompleteSessions(data.sessions);
        }
    }

    /**
     * Procesa sesiones incompletas para intentar completarlas
     * @param {Array} sessions - Lista de sesiones incompletas
     */
    async processIncompleteSessions(sessions) {
        for (const session of sessions) {
            try {
                // Evitar completar la misma sesión múltiples veces
                if (this.sessionCompletionInProgress.has(session.session_id)) {
                    console.log(`Completado de sesión ${session.session_id} ya en progreso, ignorando duplicado`);
                    continue;
                }

                this.sessionCompletionInProgress.add(session.session_id);

                try {
                    await this.completeSession(session.session_id);
                    console.log(`Sesión ${session.session_id} completada con éxito`);

                    // Notificar a los listeners que la sesión ha sido completada
                    this.notifySessionListeners('session_completion_confirmed', {
                        session_id: session.session_id,
                        receiver_id: session.receiver_id,
                        receiver_username: session.receiver_username,
                        updated_at: new Date().toISOString()
                    });
                } catch (error) {
                    console.error(`Error al completar sesión ${session.session_id}:`, error);
                } finally {
                    // Eliminar de la lista de sesiones en progreso
                    this.sessionCompletionInProgress.delete(session.session_id);
                }
            } catch (error) {
                console.error(`Error al procesar sesión incompleta ${session.session_id}:`, error);
            }
        }
    }

    /**
     * Notifica a los listeners de eventos de sesión
     * @param {string} eventType - Tipo de evento
     * @param {object} data - Datos del evento
     */
    notifySessionListeners(eventType, data) {
        if (this.sessionListeners.has(eventType)) {
            const listeners = this.sessionListeners.get(eventType);
            listeners.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error en listener de ${eventType}:`, error);
                }
            });
        }
    }

    /**
     * Registra un listener para eventos de sesión
     * @param {string} eventType - Tipo de evento
     * @param {Function} callback - Función a llamar cuando ocurre el evento
     * @returns {Function} - Función para eliminar el listener
     */
    onSessionEvent(eventType, callback) {
        if (!this.sessionListeners.has(eventType)) {
            this.sessionListeners.set(eventType, new Set());
        }

        this.sessionListeners.get(eventType).add(callback);

        // Devolver función para eliminar el listener
        return () => {
            if (this.sessionListeners.has(eventType)) {
                this.sessionListeners.get(eventType).delete(callback);
                if (this.sessionListeners.get(eventType).size === 0) {
                    this.sessionListeners.delete(eventType);
                }
            }
        };
    }

    /**
     * Registra un nuevo usuario
     * @param {string} username - Nombre de usuario
     * @param {string} password - Contraseña
     * @returns {Promise<Object>} - Respuesta del servidor
     */
    async register(username, password) {
        try {
            // Inicializar almacenamiento de claves para el usuario
            await this.keyStorage.initializeForUser(username);

            // Generar pares de claves RSA y DH en el frontend
            const { publicKey: rsaPublic, privateKey: rsaPrivate } = await this.cryptoUtils.generateRsaKeys();
            const { publicKey: dhPublic, privateKey: dhPrivate } = await this.cryptoUtils.generateDhKeys();

            // Almacenar claves privadas localmente
            await this.keyStorage.storePrivateKeys(username, rsaPrivate, dhPrivate);

            // Enviar solo las claves públicas y la contraseña al servidor
            const response = await axios.post(`${this.apiUrl}/register/`, {
                username,
                password,
                rsa_public_key: rsaPublic,
                dh_public_key: dhPublic
            });

            return response.data;
        } catch (error) {
            console.error('Error en registro:', error);
            throw error;
        }
    }

    /**
     * Inicia sesión de un usuario
     * @param {string} username - Nombre de usuario
     * @param {string} password - Contraseña
     * @returns {Promise<Object>} - Respuesta del servidor con token
     */
    async login(username, password) {
        try {
            // Enviar credenciales al servidor
            const response = await axios.post(`${this.apiUrl}/login/`, {
                username,
                password
            });

            // Guardar token en localStorage
            this.token = response.data.token;
            localStorage.setItem('token', this.token);

            // Obtener información del usuario
            const userInfo = await this.getCurrentUser();

            // Inicializar WebSocket
            WebSocketService.init();

            return {
                token: this.token,
                user: userInfo
            };
        } catch (error) {
            console.error('Error en login:', error);
            throw error;
        }
    }

    /**
     * Obtiene información del usuario actual
     * @returns {Promise<Object>} - Información del usuario
     */
    async getCurrentUser() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/get_user/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            this.currentUser = response.data;
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));

            return this.currentUser;
        } catch (error) {
            console.error('Error al obtener usuario actual:', error);
            throw error;
        }
    }

    /**
     * Cierra la sesión del usuario
     */
    logout() {
        // Desconectar WebSocket
        WebSocketService.logout();

        // Limpiar datos de sesión
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('token');
        localStorage.removeItem('currentUser');

        // Limpiar listeners y estado
        this.sessionListeners.clear();
        this.sessionCompletionInProgress.clear();

        // Eliminar manejadores de eventos WebSocket
        WebSocketService.off('session_request');
        WebSocketService.off('session_accepted');
        WebSocketService.off('session_rejected');
        WebSocketService.off('session_completed');
        WebSocketService.off('session_completion_confirmed');
        WebSocketService.off('session_closed');
        WebSocketService.off('pending_sessions');
        WebSocketService.off('incomplete_sessions');
    }

    /**
     * Inicia una nueva sesión de chat con otro usuario
     * @param {number} receiverId - ID del usuario receptor
     * @returns {Promise<Object>} - Información de la sesión iniciada
     */
    async initiateSession(receiverId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            // Generar un ID de sesión único
            const sessionId = this.cryptoUtils.generateSessionId();

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
                "initiator",
                ephemeralPrivate
            );

            // Enviar solicitud al servidor con datos ya preparados
            const response = await axios.post(
                `${this.apiUrl}/initiate_session/${receiverId}`,
                {
                    session_id: sessionId,
                    ephemeral_public: ephemeralPublic,
                    signature: signature
                },
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error al iniciar sesión de chat:', error);
            throw error;
        }
    }

    /**
     * Acepta una sesión de chat pendiente
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Información de la sesión aceptada
     */
    async acceptSession(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            // Obtener detalles de la sesión pendiente
            const pendingSessions = await this.getPendingSessions();
            const session = pendingSessions.pending_sessions.find(s => s.session_id === sessionId);

            if (!session) {
                throw new Error('Sesión pendiente no encontrada');
            }

            // Obtener información del iniciador
            const sessionData = await this.getSession(session.session_id);

            // Generar claves DH efímeras
            const { publicKey: ephemeralPublic, privateKey: ephemeralPrivate } =
                await this.cryptoUtils.generateEphemeralDhKeys();

            // Cargar clave RSA privada para firmar
            const { rsaPrivate } = await this.keyStorage.loadPrivateKeys(this.currentUser.username);

            // Firmar la clave DH pública efímera
            const signature = await this.cryptoUtils.signData(ephemeralPublic, rsaPrivate);

            // Enviar aceptación al servidor con datos ya preparados
            const response = await axios.post(
                `${this.apiUrl}/accept_session/${sessionId}`,
                {
                    ephemeral_public: ephemeralPublic,
                    signature: signature
                },
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            // Almacenar claves efímeras localmente
            await this.keyStorage.storeEphemeralKeys(
                this.currentUser.username,
                sessionId,
                "receiver",
                ephemeralPrivate,
                sessionData.initiator_ephemeral_public,
                sessionData.initiator_signature,
                sessionData.initiator_rsa_public
            );

            // Calcular secreto compartido
            const sharedSecret = await this.cryptoUtils.generateSharedSecret(
                ephemeralPrivate,
                sessionData.initiator_ephemeral_public
            );

            // Almacenar secreto compartido y derivar claves
            await this.keyStorage.storeSharedSecret(
                this.currentUser.username,
                sessionId,
                sharedSecret
            );

            return response.data;
        } catch (error) {
            console.error('Error al aceptar sesión de chat:', error);
            throw error;
        }
    }

    /**
     * Completa el establecimiento de sesión para el iniciador
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Información de la sesión completada
     */
    async completeSession(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            // Obtener sesiones activas
            const incompleteSessions = await this.getIncompleteSessions();
            const session = incompleteSessions.incomplete_sessions.find(s => s.session_id === sessionId);

            if (!session) {
                throw new Error('Sesión activa no encontrada');
            }

            // Verificar que el usuario es el iniciador
            if (session.role !== "initiator") {
                throw new Error('Solo el iniciador puede completar la sesión');
            }

            // Cargar clave privada efímera
            const { ephemeralPrivate } = await this.keyStorage.loadEphemeralKeys(
                this.currentUser.username,
                sessionId
            );

            // Almacenar clave pública efímera del receptor
            await this.keyStorage.storeEphemeralKeys(
                this.currentUser.username,
                sessionId,
                "initiator",
                ephemeralPrivate,
                session.receiver_ephemeral_public,
                session.receiver_signature,
                session.receiver_rsa_public
            );

            // Calcular secreto compartido
            const sharedSecret = await this.cryptoUtils.generateSharedSecret(
                ephemeralPrivate,
                session.receiver_ephemeral_public
            );

            // Almacenar secreto compartido y derivar claves
            await this.keyStorage.storeSharedSecret(
                this.currentUser.username,
                sessionId,
                sharedSecret
            );

            // Notificar al servidor que la sesión está completa
            const response = await axios.post(
                `${this.apiUrl}/complete_session/${sessionId}`,
                {},
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error al completar sesión de chat:', error);
            throw error;
        }
    }

    /**
     * Rechaza una sesión pendiente
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Respuesta del servidor
     */
    async rejectSession(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            const response = await axios.post(
                `${this.apiUrl}/reject_session/${sessionId}`,
                {},
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error al rechazar sesión:', error);
            throw error;
        }
    }

    /**
     * Cancela una sesión pendiente
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Respuesta del servidor
     */
    async cancelSession(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            const response = await axios.post(
                `${this.apiUrl}/cancel_session/${sessionId}`,
                {},
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            // Eliminar el directorio de la sesión
            await this.keyStorage.deleteSessionDir(
                this.currentUser.username,
                sessionId
            );

            return response.data;
        } catch (error) {
            console.error('Error al cancelar sesión:', error);
            throw error;
        }
    }

    /**
     * Cierra una sesión activa
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Respuesta del servidor
     */
    async closeSession(sessionId) {
        try {
            if (!this.token || !this.currentUser) {
                throw new Error('No hay sesión de usuario activa');
            }

            const response = await axios.post(
                `${this.apiUrl}/close_session/${sessionId}`,
                {},
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            return response.data;
        } catch (error) {
            console.error('Error al cerrar sesión:', error);
            throw error;
        }
    }

    /**
     * Obtiene las sesiones pendientes del usuario del usuario si es receptor
     * @returns {Promise<Object>} - Lista de sesiones pendientes
     */
    async getPendingSessions() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/pending_sessions/`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener sesiones pendientes recibidas:', error);
            throw error;
        }
    }

    /**
     * Obtiene las sesiones incompletas iniciadas por el usuario
     * @returns {Promise<Object>} - Lista de sesiones incompletas
     */
    async getIncompleteSessions() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/incomplete_sessions/`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener sesiones incompletas:', error);
            throw error;
        }
    }

    /**
     * Obtiene las sesiones pendientes del usuario si es iniciador
     * @returns {Promise<Object>} - Lista de sesiones pendientes
     */
    async getOutComingPendingSessions() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/out_coming_pending_sessions/`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener sesiones pendientes iniciadas:', error);
            throw error;
        }
    }

    /**
     * Obtiene las sesiones activas del usuario
     * @returns {Promise<Object>} - Lista de sesiones activas
     */
    async getActiveSessions() {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/active_sessions/`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener sesiones activas:', error);
            throw error;
        }
    }

    /**
     * Obtiene información de un usuario por su ID
     * @param {number} userId - ID del usuario
     * @returns {Promise<Object>} - Información del usuario
     */
    async getUser(userId) {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/get_user/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener usuario:', error);
            throw error;
        }
    }

    /**
     * Obtiene información de un sesión por su ID
     * @param {number} sessionId - Id de la Sesión
     * @returns {Promise<Object>} - Información del usuario
     */
    async getSession(sessionId) {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/get_session/${sessionId}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al obtener sesión:', error);
            throw error;
        }
    }

    /**
     * Busca usuarios por nombre
     * @param {string} name - Nombre a buscar
     * @returns {Promise<Object>} - Lista de usuarios encontrados
     */
    async searchUser(name) {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.get(`${this.apiUrl}/search_user/${name}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            return response.data;
        } catch (error) {
            console.error('Error al buscar usuarios:', error);
            throw error;
        }
    }

    /**
     * Verifica y completa sesiones incompletas
     * @returns {Promise<Object>} - Resultado de la operación
     */
    async checkAndCompleteSessions() {
        try {
            const incompleteSessions = await this.getIncompleteSessions();

            if (incompleteSessions && incompleteSessions.incomplete_sessions.length > 0) {
                await this.processIncompleteSessions(incompleteSessions.incomplete_sessions);
            } else {
                console.log("No hay sesiones incompletas para completar.");
            }

            return await this.getOutComingPendingSessions();
        } catch (error) {
            console.error("Error verificando y completando sesiones:", error);
            throw error;
        }
    }

    /**
     * Verifica si un usuario está en línea
     * @param {number} userId - ID del usuario
     * @returns {boolean} - true si el usuario está en línea
     */
    isUserOnline(userId) {
        return WebSocketService.isUserOnline(userId);
    }
}

export default new AuthService();


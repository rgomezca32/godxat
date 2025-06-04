import axios from 'axios';
import { KeyStorage } from './key_storage';
import { CryptoUtils } from './crypto_utils';

/**
 * Servicio de autenticación que maneja el registro, login y gestión de usuarios
 * utilizando criptografía en el frontend con Tauri
 */
export class AuthService {
    constructor() {
        this.apiUrl = 'https://godxat-api.onrender.com';
        this.keyStorage = new KeyStorage();
        this.cryptoUtils = new CryptoUtils();
        this.token = localStorage.getItem('token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
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

            console.log(userInfo)
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
            console.log(this.token)
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
        //console.log(this.token)
        //console.log(localStorage.getItem('token'))
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('token');
        localStorage.removeItem('currentUser');

        //console.log(localStorage.getItem('token'));
        //console.log(localStorage.getItem('currentUser'))
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

            console.log(this.currentUser);

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
     * Cancela una sesión iniciada si esta pendiente
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<Object>} - Información de la sesión completada
     */
    async cancelSession(sessionId) {
        try {
            if (!this.token) {
                throw new Error('No hay token de autenticación');
            }

            const response = await axios.post(`${this.apiUrl}/cancel_session/${sessionId}`, {}, // cuerpo vacío, o con datos si necesitas
                {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                }
            );

            // Elininar el directorio de la sesión
            await this.keyStorage.deleteSessionDir(
                this.currentUser.username,
                sessionId
            );

            return response.data;
        } catch (error) {
            console.error('Error al buscar usuarios:', error);
            throw error;
        }
    }

    async checkAndCompleteSessions() {
      try {
        const incompleteSessions = await this.getIncompleteSessions();
        console.log(incompleteSessions)
        if (incompleteSessions && incompleteSessions.incomplete_sessions.length > 0) {
          for (const session of incompleteSessions.incomplete_sessions) {
            try {
              const result = await this.completeSession(session.session_id);
              console.log(`Sesión ${session.session_id} completada correctamente`, result);
            } catch (completeError) {
              console.error(`Error completando sesión ${session.session_id}:`, completeError);
            }
          }
        } else {
          console.log("No hay sesiones incompletas para completar.");
        }
      } catch (error) {
        console.error("Error obteniendo sesiones incompletas:", error);
      }
    }

}

export default new AuthService();  // Exporta una instancia ya creada
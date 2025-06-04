// key_storage_web.js
// Versión web del almacenamiento de claves para desarrollo y compatibilidad

/**
 * Clase para gestionar el almacenamiento seguro de claves en el navegador
 * Esta es una versión compatible con desarrollo web que usa localStorage
 */
export class KeyStorage {
  constructor() {
    this.storagePrefix = 'secure_chat_keys_';
  }

  /**
   * Guarda las claves privadas del usuario
   * @param {string} username - Nombre de usuario
   * @param {string} rsaPrivateKey - Clave privada RSA en formato PEM
   * @param {string} dhPrivateKey - Clave privada DH en formato PEM
   * @returns {Promise<void>}
   */
  async savePrivateKeys(username, rsaPrivateKey, dhPrivateKey) {
    try {
      // Guardar clave RSA privada
      localStorage.setItem(`${this.storagePrefix}${username}_rsa_private`, rsaPrivateKey);

      // Guardar clave DH privada
      localStorage.setItem(`${this.storagePrefix}${username}_dh_private`, dhPrivateKey);

      return Promise.resolve();
    } catch (error) {
      console.error('Error al guardar claves privadas:', error);
      return Promise.reject(new Error(`No se pudieron guardar las claves privadas: ${error.message}`));
    }
  }

  /**
   * Carga las claves privadas del usuario
   * @param {string} username - Nombre de usuario
   * @returns {Promise<{rsaPrivateKey: string, dhPrivateKey: string}>} Claves privadas en formato PEM
   */
  async loadPrivateKeys(username) {
    try {
      // Cargar clave RSA privada
      const rsaPrivateKey = localStorage.getItem(`${this.storagePrefix}${username}_rsa_private`);

      // Cargar clave DH privada
      const dhPrivateKey = localStorage.getItem(`${this.storagePrefix}${username}_dh_private`);

      return Promise.resolve({ rsaPrivateKey, dhPrivateKey });
    } catch (error) {
      console.error('Error al cargar claves privadas:', error);
      return Promise.resolve({ rsaPrivateKey: null, dhPrivateKey: null });
    }
  }

  /**
   * Guarda información de una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @param {Object} sessionData - Datos de la sesión
   * @returns {Promise<void>}
   */
  async saveSession(username, sessionId, sessionData) {
    try {
      const key = `${this.storagePrefix}${username}_session_${sessionId}_data`;
      localStorage.setItem(key, JSON.stringify(sessionData));
      return Promise.resolve();
    } catch (error) {
      console.error('Error al guardar sesión:', error);
      return Promise.reject(new Error(`No se pudo guardar la sesión: ${error.message}`));
    }
  }

  /**
   * Carga información de una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @returns {Promise<Object|null>} Datos de la sesión
   */
  async loadSession(username, sessionId) {
    try {
      const key = `${this.storagePrefix}${username}_session_${sessionId}_data`;
      const sessionDataStr = localStorage.getItem(key);

      if (!sessionDataStr) {
        return Promise.resolve(null);
      }

      return Promise.resolve(JSON.parse(sessionDataStr));
    } catch (error) {
      console.error('Error al cargar sesión:', error);
      return Promise.resolve(null);
    }
  }

  /**
   * Guarda una clave efímera para una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @param {string} role - Rol en la sesión ("initiator" o "receiver")
   * @param {string} ephemeralPrivateKey - Clave DH privada efímera
   * @param {Object} peerData - Datos del otro usuario (opcional)
   * @returns {Promise<void>}
   */
  async saveEphemeralKeys(username, sessionId, role, ephemeralPrivateKey, peerData = null) {
    try {
      // Guardar clave DH privada efímera
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_ephemeral_private`,
        ephemeralPrivateKey
      );

      // Guardar rol en la sesión
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_role`,
        role
      );

      // Guardar datos del otro usuario si se proporcionan
      if (peerData) {
        if (peerData.ephemeralPublic) {
          localStorage.setItem(
            `${this.storagePrefix}${username}_session_${sessionId}_peer_ephemeral_public`,
            peerData.ephemeralPublic
          );
        }

        if (peerData.signature) {
          localStorage.setItem(
            `${this.storagePrefix}${username}_session_${sessionId}_peer_signature`,
            peerData.signature
          );
        }

        if (peerData.rsaPublic) {
          localStorage.setItem(
            `${this.storagePrefix}${username}_session_${sessionId}_peer_rsa_public`,
            peerData.rsaPublic
          );
        }
      }

      return Promise.resolve();
    } catch (error) {
      console.error('Error al guardar claves efímeras:', error);
      return Promise.reject(new Error(`No se pudieron guardar las claves efímeras: ${error.message}`));
    }
  }

  /**
   * Carga claves efímeras de una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @returns {Promise<Object>} Claves efímeras y datos relacionados
   */
  async loadEphemeralKeys(username, sessionId) {
    try {
      // Cargar clave privada efímera
      const ephemeralPrivate = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_ephemeral_private`
      );

      // Cargar clave pública efímera del otro usuario
      const peerEphemeralPublic = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_peer_ephemeral_public`
      );

      // Cargar rol
      const role = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_role`
      ) || "unknown";

      // Cargar firma del otro usuario
      const peerSignature = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_peer_signature`
      );

      // Cargar clave RSA pública del otro usuario
      const peerRsaPublic = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_peer_rsa_public`
      );

      return Promise.resolve({
        ephemeralPrivate,
        peerEphemeralPublic,
        role,
        peerSignature,
        peerRsaPublic
      });
    } catch (error) {
      console.error('Error al cargar claves efímeras:', error);
      return Promise.resolve({
        ephemeralPrivate: null,
        peerEphemeralPublic: null,
        role: null,
        peerSignature: null,
        peerRsaPublic: null
      });
    }
  }

  /**
   * Guarda claves derivadas de una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @param {ArrayBuffer} sharedSecret - Secreto compartido
   * @param {ArrayBuffer} rootKey - Clave raíz
   * @param {ArrayBuffer} chainKey - Clave de cadena
   * @returns {Promise<void>}
   */
  async saveSessionKeys(username, sessionId, sharedSecret, rootKey, chainKey) {
    try {
      // Convertir ArrayBuffers a strings base64 para almacenamiento
      const sharedSecretBase64 = btoa(String.fromCharCode(...new Uint8Array(sharedSecret)));
      const rootKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(rootKey)));
      const chainKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(chainKey)));

      // Guardar secreto compartido
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_shared_secret`,
        sharedSecretBase64
      );

      // Guardar clave raíz
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_root_key`,
        rootKeyBase64
      );

      // Guardar clave de cadena
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_chain_key`,
        chainKeyBase64
      );

      return Promise.resolve();
    } catch (error) {
      console.error('Error al guardar claves de sesión:', error);
      return Promise.reject(new Error(`No se pudieron guardar las claves de sesión: ${error.message}`));
    }
  }

  /**
   * Carga claves derivadas de una sesión
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @returns {Promise<Object>} Claves derivadas
   */
  async loadSessionKeys(username, sessionId) {
    try {
      // Cargar secreto compartido
      const sharedSecretBase64 = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_shared_secret`
      );

      // Cargar clave raíz
      const rootKeyBase64 = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_root_key`
      );

      // Cargar clave de cadena
      const chainKeyBase64 = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_chain_key`
      );

      // Convertir de base64 a ArrayBuffer
      let sharedSecret = null;
      let rootKey = null;
      let chainKey = null;

      if (sharedSecretBase64) {
        const binaryString = atob(sharedSecretBase64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        sharedSecret = bytes.buffer;
      }

      if (rootKeyBase64) {
        const binaryString = atob(rootKeyBase64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        rootKey = bytes.buffer;
      }

      if (chainKeyBase64) {
        const binaryString = atob(chainKeyBase64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        chainKey = bytes.buffer;
      }

      return Promise.resolve({
        sharedSecret,
        rootKey,
        chainKey
      });
    } catch (error) {
      console.error('Error al cargar claves de sesión:', error);
      return Promise.resolve({
        sharedSecret: null,
        rootKey: null,
        chainKey: null
      });
    }
  }

  /**
   * Guarda una clave de mensaje
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @param {number} messageNumber - Número de mensaje
   * @param {ArrayBuffer} messageKey - Clave de mensaje
   * @returns {Promise<void>}
   */
  async saveMessageKey(username, sessionId, messageNumber, messageKey) {
    try {
      // Convertir ArrayBuffer a string base64 para almacenamiento
      const messageKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(messageKey)));

      // Guardar clave de mensaje
      localStorage.setItem(
        `${this.storagePrefix}${username}_session_${sessionId}_message_key_${messageNumber}`,
        messageKeyBase64
      );

      return Promise.resolve();
    } catch (error) {
      console.error('Error al guardar clave de mensaje:', error);
      return Promise.reject(new Error(`No se pudo guardar la clave de mensaje: ${error.message}`));
    }
  }

  /**
   * Carga una clave de mensaje
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @param {number} messageNumber - Número de mensaje
   * @returns {Promise<ArrayBuffer|null>} Clave de mensaje
   */
  async loadMessageKey(username, sessionId, messageNumber) {
    try {
      // Cargar clave de mensaje
      const messageKeyBase64 = localStorage.getItem(
        `${this.storagePrefix}${username}_session_${sessionId}_message_key_${messageNumber}`
      );

      if (!messageKeyBase64) {
        return Promise.resolve(null);
      }

      // Convertir de base64 a ArrayBuffer
      const binaryString = atob(messageKeyBase64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      return Promise.resolve(bytes.buffer);
    } catch (error) {
      console.error('Error al cargar clave de mensaje:', error);
      return Promise.resolve(null);
    }
  }

  /**
   * Elimina una sesión y todas sus claves
   * @param {string} username - Nombre de usuario
   * @param {string} sessionId - ID de la sesión
   * @returns {Promise<boolean>} true si se eliminó correctamente
   */
  async deleteSession(username, sessionId) {
    try {
      // Obtener todas las claves en localStorage
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.includes(`${this.storagePrefix}${username}_session_${sessionId}`)) {
          keys.push(key);
        }
      }

      // Eliminar todas las claves relacionadas con la sesión
      keys.forEach(key => localStorage.removeItem(key));

      return Promise.resolve(true);
    } catch (error) {
      console.error('Error al eliminar sesión:', error);
      return Promise.resolve(false);
    }
  }

  /**
   * Elimina todas las claves de un usuario
   * @param {string} username - Nombre de usuario
   * @returns {Promise<boolean>} true si se eliminó correctamente
   */
  async deleteUserKeys(username) {
    try {
      // Obtener todas las claves en localStorage
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.includes(`${this.storagePrefix}${username}`)) {
          keys.push(key);
        }
      }

      // Eliminar todas las claves relacionadas con el usuario
      keys.forEach(key => localStorage.removeItem(key));

      return Promise.resolve(true);
    } catch (error) {
      console.error('Error al eliminar claves de usuario:', error);
      return Promise.resolve(false);
    }
  }
}

// Exportar una instancia única para usar en toda la aplicación
export const keyStorage = new KeyStorage();

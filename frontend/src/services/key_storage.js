// key_storage.js
import {invoke} from '@tauri-apps/api/core';
import {BaseDirectory, create, exists, mkdir, open, readTextFile, remove} from '@tauri-apps/plugin-fs';

/**
 * Clase para el almacenamiento seguro de claves en el sistema de archivos local
 * a través de Tauri
 */
export class KeyStorage {
    constructor() {
        this.keyDir = 'godxatkeys';
    }

    async ensureDirExists(path) {
        const existDir = await exists(path, {baseDir: BaseDirectory.AppLocalData,});
        if (existDir){
            return true;
        }
        else{
            await mkdir(path, { baseDir: BaseDirectory.AppLocalData });
        }
    }

    async deleteDir(path) {
        await remove(path, {
          baseDir: BaseDirectory.AppLocalData,
          recursive: true,
        });
    }

    async existFile(path) {
        return await exists(path, {
            baseDir: BaseDirectory.AppLocalData,
        })
    }

    /**
     * Inicializa el almacenamiento de claves para un usuario
     * @param {string} username - Nombre de usuario
     * @returns {Promise<void>}
     */
    async initializeForUser(username) {
      try {
        const basePath = this.keyDir; // raíz de tu almacenamiento local
        const userDir = `${basePath}/${username}`;
        const sessionsDir = `${userDir}/sessions`;

        // Asegurar que cada directorio existe
        await this.ensureDirExists(basePath);
        await this.ensureDirExists(userDir);
        await this.ensureDirExists(sessionsDir);

        return true;
      } catch (error) {
        console.error('Error al inicializar almacenamiento de claves:', error);
        throw error;
      }
    }

    /**
     * Guarda las claves privadas del usuario
     * @param {string} username - Nombre de usuario
     * @param {string} rsaPrivate - Clave RSA privada en formato PEM
     * @param {string} dhPrivate - Clave DH privada en formato Base64
     * @returns {Promise<boolean>}
     */
    async storePrivateKeys(username, rsaPrivate, dhPrivate) {
        try {
            const userDir = `${this.keyDir}/${username}`;

            // Guardar clave RSA privada
            let file = await open(`${userDir}/rsa_private.pem`, {
              write: true,
              create: true,
              baseDir: BaseDirectory.AppData,
            });
            await file.write(new TextEncoder().encode(rsaPrivate));
            await file.close();

            // Guardar clave DH privada
            file = await open(`${userDir}/dh_private.b64`, {
              write: true,
              create: true,
              baseDir: BaseDirectory.AppData,
            });
            await file.write(new TextEncoder().encode(dhPrivate));
            await file.close();

            return true;
        } catch (error) {
            console.error('Error al guardar claves privadas:', error);
            throw error;
        }
    }

    /**
     * Carga las claves privadas del usuario
     * @param {string} username - Nombre de usuario
     * @returns {Promise<{rsaPrivate: string, dhPrivate: string}>}
     */
    async loadPrivateKeys(username) {
        try {
            const userDir = `${this.keyDir}/${username}`;

            // Verificar si existen las claves
            const rsaExists = await exists(`${userDir}/rsa_private.pem`, { baseDir: BaseDirectory.AppLocalData, });
            const dhExists = await exists(`${userDir}/dh_private.b64`, { baseDir: BaseDirectory.AppLocalData, });

            if (!rsaExists || !dhExists) {
                throw new Error('No se encontraron las claves privadas');
            }

            let file = await open(`${userDir}/rsa_private.pem`, {
              read: true,
              baseDir: BaseDirectory.AppData,
            });
            let stat = await file.stat();
            let buf = new Uint8Array(stat.size);
            await file.read(buf);
            const rsaPrivate = new TextDecoder().decode(buf);
            await file.close();

            file = await open(`${userDir}/dh_private.b64`, {
              read: true,
              baseDir: BaseDirectory.AppData,
            });
            stat = await file.stat();
            buf = new Uint8Array(stat.size);
            await file.read(buf);
            const dhPrivate = new TextDecoder().decode(buf);
            await file.close();

            return { rsaPrivate, dhPrivate };
        } catch (error) {
            console.error('Error al cargar claves privadas:', error);
            throw error;
        }
    }

    /**
     * Inicializa una sesión y almacena las claves efímeras
     * @param {string} username - Nombre de usuario
     * @param {string} sessionId - ID de la sesión
     * @param {string} role - Rol en la sesión ('initiator' o 'receiver')
     * @param {string} ephemeralPrivate - Clave DH privada efímera
     * @param {string} peerEphemeralPublic - Clave DH pública efímera del otro usuario (opcional)
     * @param {string} peerSignature - Firma de la clave DH pública del otro usuario (opcional)
     * @param {string} peerRsaPublic - Clave RSA pública del otro usuario (opcional)
     * @returns {Promise<boolean>}
     */
    async storeEphemeralKeys(username, sessionId, role, ephemeralPrivate, peerEphemeralPublic = null, peerSignature = null, peerRsaPublic = null) {
        try {
            const userDir = `${this.keyDir}/${username}`;
            const sessionDir = `${userDir}/sessions/${sessionId}`;

            // Crear directorio de sesión
            await this.ensureDirExists(sessionDir)

            if (!await this.existFile(`${sessionDir}/ephemeral_private.b64`)){
                // Guardar clave DH privada efímera
                let file = await open(`${sessionDir}/ephemeral_private.b64`, {
                  write: true,
                  create: true,
                  baseDir: BaseDirectory.AppData,
                });
                await file.write(new TextEncoder().encode(ephemeralPrivate));
                await file.close();
            }

            if (!await this.existFile(`${sessionDir}/role.txt`)){
                // Guardar rol en la sesión
                let file = await open(`${sessionDir}/role.txt`, {
                  write: true,
                  create: true,
                  baseDir: BaseDirectory.AppData,
                });
                await file.write(new TextEncoder().encode(role));
                await file.close();
            }

            if (!await this.existFile(`${sessionDir}/peer_ephemeral_public.b64`)){
                // Guardar la clave efimera del otro usuario
                let file = await open(`${sessionDir}/peer_ephemeral_public.b64`, {
                  write: true,
                  create: true,
                  baseDir: BaseDirectory.AppData,
                });
                await file.write(new TextEncoder().encode(peerEphemeralPublic));
                await file.close();
            }

            if (!await this.existFile(`${sessionDir}/peer_rsa_public.pem`)){
                // Guardar la clave rsa publica del otro usuario
                let file = await open(`${sessionDir}/peer_rsa_public.pem`, {
                  write: true,
                  create: true,
                  baseDir: BaseDirectory.AppData,
                });
                await file.write(new TextEncoder().encode(peerRsaPublic));
                await file.close();
            }

            if (!await this.existFile(`${sessionDir}/peer_signature.txt`)){
                // Guardar la firma del otro usuario
                let file = await open(`${sessionDir}/peer_signature.txt`, {
                  write: true,
                  create: true,
                  baseDir: BaseDirectory.AppData,
                });
                await file.write(new TextEncoder().encode(peerSignature));
                await file.close();
            }

            return true;
        } catch (error) {
            console.error('Error al guardar claves efímeras:', error);
            throw error;
        }
    }

    /**
     * Carga las claves efímeras de una sesión
     * @param {string} username - Nombre de usuario
     * @param {string} sessionId - ID de la sesión
     * @returns {Promise<{ephemeralPrivate: string, peerEphemeralPublic: string, role: string, peerSignature: string, peerRsaPublic: string}>}
     */
    async loadEphemeralKeys(username, sessionId) {
        try {
            const userDir = `${this.keyDir}/${username}`;
            const sessionDir = `${userDir}/sessions/${sessionId}`;

            // Verificar si existe el directorio de sesión
            const sessionExists = await exists(sessionDir, { baseDir: BaseDirectory.AppLocalData, });
            if (!sessionExists) {
                throw new Error('No se encontró la sesión');
            }

            // Verificar si existe  clave privada efímera
            let ephemeralPrivate = null;
            const ephemeralPrivateExists = await exists(`${sessionDir}/ephemeral_private.b64`, { baseDir: BaseDirectory.AppLocalData, });
            if (!ephemeralPrivateExists) {
                throw new Error('No se encontró la clave privada efímera');
            }
            else{
                let file = await open(`${sessionDir}/ephemeral_private.b64`, {
                  read: true,
                  baseDir: BaseDirectory.AppData,
                });
                let stat = await file.stat();
                let buf = new Uint8Array(stat.size);
                await file.read(buf);
                ephemeralPrivate = new TextDecoder().decode(buf);
                await file.close();
            }

            // Cargar rol en la sesión
            let role = 'unknown';
            const roleExists = await exists(`${sessionDir}/role.txt`, { baseDir: BaseDirectory.AppLocalData, });
            if (roleExists) {
                let file = await open(`${sessionDir}/role.txt`, {
                  read: true,
                  baseDir: BaseDirectory.AppData,
                });
                let stat = await file.stat();
                let buf = new Uint8Array(stat.size);
                await file.read(buf);
                role = new TextDecoder().decode(buf);
                await file.close();
            }

            // Cargar clave DH pública efímera del otro usuario
            let peerEphemeralPublic = null;
            const peerEphemeralPublicExists = await exists(`${sessionDir}/peer_ephemeral_public.b64`, { baseDir: BaseDirectory.AppLocalData, });
            if (peerEphemeralPublicExists) {
                let file = await open(`${sessionDir}/peer_ephemeral_public.b64`, {
                  read: true,
                  baseDir: BaseDirectory.AppData,
                });
                let stat = await file.stat();
                let buf = new Uint8Array(stat.size);
                await file.read(buf);
                peerEphemeralPublic = new TextDecoder().decode(buf);
                await file.close();
            }

            // Cargar firma de la clave DH pública del otro usuario
            let peerSignature = null;
            const peerSignatureExists = await exists(`${sessionDir}/peer_signature.txt`, { baseDir: BaseDirectory.AppLocalData, });
            if (peerSignatureExists) {
                let file = await open(`${sessionDir}/peer_signature.txt`, {
                  read: true,
                  baseDir: BaseDirectory.AppData,
                });
                let stat = await file.stat();
                let buf = new Uint8Array(stat.size);
                await file.read(buf);
                peerSignature = new TextDecoder().decode(buf);
                await file.close();
            }

            // Cargar clave RSA pública del otro usuario
            let peerRsaPublic = null;
            const peerRsaPublicExists = await exists(`${sessionDir}/peer_rsa_public.pem`, { baseDir: BaseDirectory.AppLocalData, });
            if (peerRsaPublicExists) {
                let file = await open(`${sessionDir}/peer_rsa_public.pem`, {
                  read: true,
                  baseDir: BaseDirectory.AppData,
                });
                let stat = await file.stat();
                let buf = new Uint8Array(stat.size);
                await file.read(buf);
                peerRsaPublic = new TextDecoder().decode(buf);
                await file.close();
            }

            return { ephemeralPrivate, peerEphemeralPublic, role, peerSignature, peerRsaPublic };
        } catch (error) {
            console.error('Error al cargar claves efímeras:', error);
            throw error;
        }
    }

    /**
     * Almacena el secreto compartido y las claves derivadas
     * @param {string} username - Nombre de usuario
     * @param {string} sessionId - ID de la sesión
     * @param {string} sharedSecret - Secreto compartido
     * @returns {Promise<{rootKey: string, chainKey: string}>}
     */
    async storeSharedSecret(username, sessionId, sharedSecret) {
        try {
            const userDir = `${this.keyDir}/${username}`;
            const sessionDir = `${userDir}/sessions/${sessionId}`;
            const messageDir = `${sessionDir}/message_keys`;

            // Crear directorio de claves de mensaje
            await this.ensureDirExists(messageDir);

            // Guardar secreto compartido
            await create(`${sessionDir}/shared_secret.b64`, { baseDir: BaseDirectory.AppData, });
            let file = await open(`${sessionDir}/shared_secret.b64`, {
              write: true,
              create: true,
              baseDir: BaseDirectory.AppData,
            });
            await file.write(new TextEncoder().encode(sharedSecret));
            await file.close();

            // Derivar clave raíz
            const rootKey = await this.deriveRootKey(sharedSecret);
            file = await open(`${sessionDir}/root_key.b64`, {
              write: true,
              create: true,
              baseDir: BaseDirectory.AppData,
            });
            await file.write(new TextEncoder().encode(rootKey));
            await file.close();

            // Derivar clave de cadena
            const chainKey = await this.deriveChainKey(rootKey);
            file = await open(`${sessionDir}/chain_key.b64`, {
              write: true,
              create: true,
              baseDir: BaseDirectory.AppData,
            });
            await file.write(new TextEncoder().encode(chainKey));
            await file.close();

            return { rootKey, chainKey };
        } catch (error) {
            console.error('Error al guardar secreto compartido:', error);
            throw error;
        }
    }

    /**
     * Elimina el directorio de la sesión
     * @param {string} username - Nombre de usuario
     * @param {string} sessionId - ID de la sesión
     * @param {string} sharedSecret - Secreto compartido
     * @returns {Promise<{rootKey: string, chainKey: string}>}
     */
    async deleteSessionDir(username, sessionId) {
        try {
            const userDir = `${this.keyDir}/${username}`;
            const sessionDir = `${userDir}/sessions/${sessionId}`;

            await this.deleteDir(sessionDir)

        } catch (error) {
            console.error('Error al eliminar el directorio de la sesión:', error);
            throw error;
        }
    }

    /**
     * Deriva una clave raíz a partir del secreto compartido
     * @param {string} sharedSecret - Secreto compartido en formato Base64
     * @returns {Promise<string>} - Clave raíz en formato Base64
     */
    async deriveRootKey(sharedSecret) {
        try {
            // Usar HMAC para derivar la clave raíz
            const rootKey = await invoke('hmac_sha256', {
                key: sharedSecret,
                data: 'root_key'
            });
            return rootKey;
        } catch (error) {
            // Si la función de Rust no está disponible, implementar en JS
            const encoder = new TextEncoder();
            const keyData = this.base64ToArrayBuffer(sharedSecret);
            const messageData = encoder.encode('root_key');

            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );

            const signature = await crypto.subtle.sign(
                'HMAC',
                key,
                messageData
            );

            return this.arrayBufferToBase64(signature);
        }
    }

    /**
     * Deriva una clave de cadena a partir de la clave raíz
     * @param {string} rootKey - Clave raíz en formato Base64
     * @returns {Promise<string>} - Clave de cadena en formato Base64
     */
    async deriveChainKey(rootKey) {
        try {
            // Usar HMAC para derivar la clave de cadena
            const chainKey = await invoke('hmac_sha256', {
                key: rootKey,
                data: 'chain_key'
            });
            return chainKey;
        } catch (error) {
            // Si la función de Rust no está disponible, implementar en JS
            const encoder = new TextEncoder();
            const keyData = this.base64ToArrayBuffer(rootKey);
            const messageData = encoder.encode('chain_key');

            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );

            const signature = await crypto.subtle.sign(
                'HMAC',
                key,
                messageData
            );

            return this.arrayBufferToBase64(signature);
        }
    }

    /**
     * Deriva una clave de mensaje específica para un número de mensaje
     * @param {string} username - Nombre de usuario
     * @param {string} sessionId - ID de la sesión
     * @param {number} messageNumber - Número de mensaje
     * @returns {Promise<string>} - Clave de mensaje en formato Base64
     */
    async deriveMessageKey(username, sessionId, messageNumber) {
        try {
            const userDir = `${this.keyDir}/${username}`;
            const sessionDir = `${userDir}/sessions/${sessionId}`;
            const messageKeyDir = `${sessionDir}/message_keys`;

            // Verificar si existe el directorio de sesión
            const sessionExists = await exists(sessionDir, { baseDir: BaseDirectory.AppLocalData });
            if (!sessionExists) {
                throw new Error('No se encontró la sesión');
            }

            // Verificar si ya existe la clave de mensaje (para reutilización)
            const messageKeyPath = `${messageKeyDir}/${messageNumber}.b64`;
            const messageKeyExists = await exists(messageKeyPath, { baseDir: BaseDirectory.AppLocalData });

            if (messageKeyExists) {
                // Reutilizar clave de mensaje existente
                return await readTextFile(messageKeyPath, { baseDir: BaseDirectory.AppLocalData });
            }

            // Cargar clave de cadena
            const chainKeyPath = `${sessionDir}/chain_key.b64`;
            const chainKeyExists = await exists(chainKeyPath, { baseDir: BaseDirectory.AppLocalData });

            if (!chainKeyExists) {
                throw new Error('No se encontró la clave de cadena');
            }

            const chainKey = await readTextFile(chainKeyPath, { baseDir: BaseDirectory.AppLocalData });

            // Derivar clave de mensaje específica para este número de mensaje
            const messageKeyInput = `message_key_${messageNumber}`;
            let messageKey;

            try {
                // Intentar usar la función nativa de Rust
                messageKey = await invoke('hmac_sha256', {
                    key: chainKey,
                    data: messageKeyInput
                });
            } catch (error) {
                // Fallback a implementación JS
                const encoder = new TextEncoder();
                const keyData = this.base64ToArrayBuffer(chainKey);
                const messageData = encoder.encode(messageKeyInput);

                const key = await crypto.subtle.importKey(
                    'raw',
                    keyData,
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                );

                const signature = await crypto.subtle.sign(
                    'HMAC',
                    key,
                    messageData
                );

                messageKey = this.arrayBufferToBase64(signature);
            }

            // Almacenar la clave de mensaje para referencia futura
            await this.ensureDirExists(messageKeyDir);

            let file = await open(messageKeyPath, {
                write: true,
                create: true,
                baseDir: BaseDirectory.AppLocalData,
            });
            await file.write(new TextEncoder().encode(messageKey));
            await file.close();

            return messageKey;
        } catch (error) {
            console.error('Error al derivar clave de mensaje:', error);
            throw error;
        }
    }

    // Métodos auxiliares para conversión de formatos
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
}

export const keyStorage = new KeyStorage();

// key_storage_factory.js
// Factory para proporcionar la implementación correcta de almacenamiento de claves según el entorno

import { keyStorage as webKeyStorage } from './key_storage_web';
import { isTauri } from '@tauri-apps/api/core';

// Variable para almacenar la instancia de almacenamiento
let storageInstance = null;

/**
 * Detecta si la aplicación está ejecutándose en entorno Tauri
 * @returns {Promise<boolean>} true si está en Tauri, false si está en web
 */
async function isTauriEnvironment() {
  try {
    // Usar la función isTauri de @tauri-apps/api/core
    return isTauri();
  } catch (error) {
    // Si hay un error al importar, estamos en un navegador web
    return false;
  }
}

/**
 * Obtiene la instancia de almacenamiento adecuada para el entorno actual
 * @returns {Promise<Object>} Instancia de almacenamiento
 */
export async function getKeyStorage() {
  // Si ya tenemos una instancia, la devolvemos
  if (storageInstance) {
    return storageInstance;
  }

  try {
    // Comprobar si estamos en Tauri
    const isTauri = await isTauriEnvironment();

    if (isTauri) {
      // En Tauri, importar dinámicamente la implementación nativa
      const { keyStorage: tauriKeyStorage } = await import('./key_storage');
      storageInstance = tauriKeyStorage;
    } else {
      // En web, usar la implementación web
      storageInstance = webKeyStorage;
    }

    return storageInstance;
  } catch (error) {
    console.error('Error al inicializar el almacenamiento de claves:', error);
    // En caso de error, usar la implementación web como fallback
    storageInstance = webKeyStorage;
    return storageInstance;
  }
}

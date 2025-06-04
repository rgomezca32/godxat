use tauri::{
  Builder,
  generate_context,
};

use dirs_next::{data_dir, config_dir, document_dir};
use std::path::PathBuf;

#[tauri::command]
fn list_files_in_directory(path: String, base_dir: String) -> Result<Vec<String>, String> {
    let base_directory: PathBuf = match base_dir.as_str() {
        "AppData" => data_dir().ok_or_else(|| "No se pudo obtener el directorio AppData".to_string())?,
        "AppLocalData" => config_dir().ok_or_else(|| "No se pudo obtener el directorio AppLocalData".to_string())?,
        "Document" => document_dir().ok_or_else(|| "No se pudo obtener el directorio Document".to_string())?,
        _ => return Err("Directorio base no válido".to_string()),
    };

    let full_path = base_directory.join(path);

    if !full_path.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(&full_path)
        .map_err(|e| format!("Error al leer el directorio {:?}: {}", full_path, e))?;

    let mut files = Vec::new();
    for entry in entries {
        if let Ok(entry) = entry {
            if let Some(file_name) = entry.file_name().to_str() {
                files.push(file_name.to_string());
            }
        }
    }

    Ok(files)
}

// Nuevas funciones para operaciones criptográficas
#[tauri::command]
fn generate_rsa_keys() -> Result<(String, String), String> {
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, EncodePrivateKey}};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let bits = 2048;

    // Generar clave privada RSA
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| format!("Error al generar clave RSA: {}", e))?;

    // Derivar clave pública
    let public_key = RsaPublicKey::from(&private_key);

    // Serializar claves a formato PEM
    let private_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| format!("Error al serializar clave privada: {}", e))?
        .to_string();

    let public_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| format!("Error al serializar clave pública: {}", e))?;

    Ok((public_pem, private_pem))
}

#[tauri::command]
fn generate_dh_keys() -> Result<(String, String), String> {
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Generar clave privada X25519 (más moderna y segura que DH clásico)
    let private_key = StaticSecret::random_from_rng(OsRng);

    // Derivar clave pública
    let public_key = PublicKey::from(&private_key);

    // Serializar claves a formato Base64
    let private_bytes = private_key.to_bytes();
    let public_bytes = public_key.to_bytes();

    let private_b64 = BASE64.encode(private_bytes);
    let public_b64 = BASE64.encode(public_bytes);

    Ok((public_b64, private_b64))
}

#[tauri::command]
fn sign_data(data: String, private_key_pem: String) -> Result<String, String> {
    use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, pss::{SigningKey, BlindedSigningKey}};
    use rsa::signature::{RandomizedSigner, SignatureEncoding}; // <- importa SignatureEncoding aquí
    use sha2::Sha256;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rand::thread_rng; // <- importa rand::thread_rng para el generador RNG

    // Cargar clave privada RSA
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| format!("Error al cargar clave privada: {}", e))?;

    // Crear firmante PSS
    let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
    let blinded_signing_key = BlindedSigningKey::<Sha256>::new(signing_key.into());

    // Firmar datos usando thread_rng como generador de números aleatorios
    let signature = blinded_signing_key.sign_with_rng(&mut thread_rng(), data.as_bytes());

    // Codificar firma en base64
    let signature_b64 = BASE64.encode(signature.to_bytes());

    Ok(signature_b64)
}

#[tauri::command]
fn verify_signature(data: String, signature_base64: String, public_key_pem: String) -> Result<bool, String> {
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, pss::{VerifyingKey}};
    use rsa::pss::Signature;
    use rsa::signature::Verifier;
    use sha2::Sha256;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decodificar firma de base64
    let signature_bytes = BASE64.decode(signature_base64.as_bytes())
        .map_err(|e| format!("Error al decodificar firma: {}", e))?;

    // Cargar clave pública RSA
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)
        .map_err(|e| format!("Error al cargar clave pública: {}", e))?;

    // Crear verificador PSS
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);

    // Verificar firma
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| "Formato de firma inválido".to_string())?;

    match verifying_key.verify(data.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false)
    }
}

#[tauri::command]
fn generate_shared_secret(private_key_b64: String, public_key_b64: String) -> Result<String, String> {
    use x25519_dalek::{StaticSecret, PublicKey};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Sha256, Digest};

    // Decodificar claves de base64
    let private_bytes = BASE64.decode(private_key_b64.as_bytes())
        .map_err(|e| format!("Error al decodificar clave privada: {}", e))?;

    let public_bytes = BASE64.decode(public_key_b64.as_bytes())
        .map_err(|e| format!("Error al decodificar clave pública: {}", e))?;

    // Convertir a tipos X25519
    let mut private_key_array = [0u8; 32];
    let mut public_key_array = [0u8; 32];

    if private_bytes.len() != 32 || public_bytes.len() != 32 {
        return Err("Tamaño de clave inválido".to_string());
    }

    private_key_array.copy_from_slice(&private_bytes);
    public_key_array.copy_from_slice(&public_bytes);

    let private_key = StaticSecret::from(private_key_array);
    let public_key = PublicKey::from(public_key_array);

    // Calcular secreto compartido
    let shared_secret = private_key.diffie_hellman(&public_key);

    // Derivar clave criptográfica del secreto compartido
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    let derived_key = hasher.finalize();

    // Codificar en base64
    let secret_b64 = BASE64.encode(derived_key);

    Ok(secret_b64)
}

#[tauri::command]
fn encrypt_message_aes(message: String, key_b64: String) -> Result<String, String> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::{aead::Aead, KeyInit};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rand::Rng;

    // Decodificar clave de base64
    let key_bytes = BASE64.decode(key_b64.as_bytes())
        .map_err(|e| format!("Error al decodificar clave: {}", e))?;

    // Asegurar que la clave tenga el tamaño correcto para AES-256
    if key_bytes.len() < 32 {
        return Err("Clave demasiado corta para AES-256".to_string());
    }

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes[0..32]);
    let cipher = Aes256Gcm::new(key);

    // Generar nonce aleatorio
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Cifrar el mensaje
    let ciphertext = cipher.encrypt(nonce, message.as_bytes().as_ref())
        .map_err(|e| format!("Error al cifrar: {}", e))?;

    // Combinar nonce y ciphertext y codificar en base64
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    let encrypted_b64 = BASE64.encode(result);

    Ok(encrypted_b64)
}

#[tauri::command]
fn decrypt_message_aes(encrypted_b64: String, key_b64: String) -> Result<String, String> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::{aead::Aead, KeyInit};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decodificar mensaje cifrado y clave de base64
    let encrypted_data = BASE64.decode(encrypted_b64.as_bytes())
        .map_err(|e| format!("Error al decodificar mensaje cifrado: {}", e))?;

    let key_bytes = BASE64.decode(key_b64.as_bytes())
        .map_err(|e| format!("Error al decodificar clave: {}", e))?;

    // Verificar tamaños
    if encrypted_data.len() <= 12 {
        return Err("Mensaje cifrado demasiado corto".to_string());
    }

    if key_bytes.len() < 32 {
        return Err("Clave demasiado corta para AES-256".to_string());
    }

    // Extraer nonce y ciphertext
    let nonce = Nonce::from_slice(&encrypted_data[0..12]);
    let ciphertext = &encrypted_data[12..];

    // Configurar cifrador
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes[0..32]);
    let cipher = Aes256Gcm::new(key);

    // Descifrar el mensaje
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Error al descifrar: {}", e))?;

    // Convertir a string
    let message = String::from_utf8(plaintext)
        .map_err(|e| format!("Error al convertir mensaje descifrado a texto: {}", e))?;

    Ok(message)
}

#[tauri::command]
fn hash_password(password: String) -> Result<String, String> {
    use argon2::{
        password_hash::{
            rand_core::OsRng,
            PasswordHasher, SaltString
        },
        Argon2
    };

    // Generar salt aleatorio
    let salt = SaltString::generate(&mut OsRng);

    // Configurar Argon2
    let argon2 = Argon2::default();

    // Hashear la contraseña
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Error al hashear contraseña: {}", e))?
        .to_string();

    Ok(password_hash)
}

#[tauri::command]
fn verify_password(password: String, password_hash: String) -> Result<bool, String> {
    use argon2::{
        password_hash::{
            PasswordHash, PasswordVerifier
        },
        Argon2
    };

    // Parsear el hash
    let parsed_hash = PasswordHash::new(&password_hash)
        .map_err(|e| format!("Error al parsear hash: {}", e))?;

    // Verificar la contraseña
    let argon2 = Argon2::default();
    let result = argon2.verify_password(password.as_bytes(), &parsed_hash);

    Ok(result.is_ok())
}

#[tauri::command]
fn hmac_sha256(key: String, data: String) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decodificar clave de base64
    let key_bytes = BASE64.decode(key.as_bytes())
        .map_err(|e| format!("Error al decodificar clave: {}", e))?;

    // Crear HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
        .map_err(|e| format!("Error al crear HMAC: {}", e))?;

    // Actualizar con los datos
    mac.update(data.as_bytes());

    // Finalizar y obtener resultado
    let result = mac.finalize().into_bytes();

    // Codificar en base64
    let result_b64 = BASE64.encode(result);

    Ok(result_b64)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  Builder::default()
    .plugin(tauri_plugin_updater::Builder::new().build())
    .plugin(tauri_plugin_fs::init())
    .plugin(tauri_plugin_http::init())
    .plugin(tauri_plugin_dialog::init())
    .plugin(tauri_plugin_log::Builder::default()
      .level(log::LevelFilter::Info)
      .build()
    )
    .invoke_handler(tauri::generate_handler![
        list_files_in_directory,
        generate_rsa_keys,
        generate_dh_keys,
        sign_data,
        verify_signature,
        generate_shared_secret,
        encrypt_message_aes,
        decrypt_message_aes,
        hash_password,
        verify_password,
        hmac_sha256
    ])
    .run(generate_context!())
    .expect("error while running tauri application");
}

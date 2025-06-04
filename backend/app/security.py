from datetime import datetime, timedelta
from jose import jwt
from typing import Optional
import os
from dotenv import load_dotenv

# Configuración para JWT
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Crea un token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Nota: Todas las funciones criptográficas han sido eliminadas
# Las siguientes funciones son solo stubs para mantener compatibilidad con el código existente
# pero no realizan ninguna operación criptográfica real

def hash_password(password):
    """
    Esta función ya no hashea contraseñas en el backend.
    Ahora solo recibe el hash generado por el frontend.
    """
    return password  # Simplemente devuelve el hash recibido

def verify_password(plain_password, hashed_password):
    """
    Esta función ya no verifica contraseñas en el backend.
    La verificación se realiza en el frontend.
    """
    return True  # La verificación real ocurre en el frontend

# Las siguientes funciones son stubs vacíos para mantener compatibilidad
# Todas estas operaciones ahora se realizan en el frontend/Tauri

def generate_rsa_keys():
    """Esta función ya no genera claves RSA en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def generate_dh_keys():
    """Esta función ya no genera claves DH en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def generate_ephemeral_dh_keys():
    """Esta función ya no genera claves DH efímeras en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def sign_data_with_rsa(data, rsa_private_key_pem):
    """Esta función ya no firma datos en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def verify_signature_with_rsa(data, signature_base64, rsa_public_key_pem):
    """Esta función ya no verifica firmas en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def generate_shared_secret(private_key_pem, public_key_pem_str):
    """Esta función ya no genera secretos compartidos en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def encrypt_message_aes(message, key):
    """Esta función ya no cifra mensajes en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

def decrypt_message_aes(encrypted_message, key):
    """Esta función ya no descifra mensajes en el backend."""
    raise NotImplementedError("Esta operación debe realizarse en el frontend")

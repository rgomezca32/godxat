from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
import bcrypt
from datetime import datetime, timedelta
from jose import jwt
from typing import Optional
from dotenv import load_dotenv

# Configuración para JWT
load_dotenv()  # Carga las variables del archivo .env
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Parámetros para Diffie-Hellman
# Estos son parámetros estándar para DH de 2048 bits
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())


def generate_rsa_keys():
    """Genera un par de claves RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Serializar las claves
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem.decode(), private_pem


def generate_dh_keys():
    """Genera un par de claves Diffie-Hellman reales"""
    # Generar una clave privada DH usando los parámetros definidos
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()

    # Serializar las claves
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem.decode(), private_pem


def generate_ephemeral_dh_keys():
    """Genera un par de claves Diffie-Hellman efímeras para una sesión"""
    return generate_dh_keys()


def sign_data_with_rsa(data, rsa_private_key_pem):
    """
    Firma datos usando la clave privada RSA

    Args:
        data: Datos a firmar (bytes o string)
        rsa_private_key_pem: Clave privada RSA en formato PEM

    Returns:
        signature: Firma digital en formato base64
    """
    # Convertir datos a bytes si es necesario
    if isinstance(data, str):
        data = data.encode()

    # Cargar la clave privada RSA
    private_key = serialization.load_pem_private_key(
        rsa_private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Firmar los datos
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Codificar la firma en base64
    return base64.b64encode(signature).decode()


def verify_signature_with_rsa(data, signature_base64, rsa_public_key_pem):
    """
    Verifica una firma usando la clave pública RSA

    Args:
        data: Datos originales (bytes o string)
        signature_base64: Firma digital en formato base64
        rsa_public_key_pem: Clave pública RSA en formato PEM

    Returns:
        valid: True si la firma es válida, False en caso contrario
    """
    # Convertir datos a bytes si es necesario
    if isinstance(data, str):
        data = data.encode()

    # Decodificar la firma de base64
    signature = base64.b64decode(signature_base64)

    # Cargar la clave pública RSA
    if isinstance(rsa_public_key_pem, str):
        rsa_public_key_pem = rsa_public_key_pem.encode()

    public_key = serialization.load_pem_public_key(
        rsa_public_key_pem,
        backend=default_backend()
    )

    try:
        # Verificar la firma
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def generate_shared_secret(private_key_pem, public_key_pem_str):
    """
    Genera un secreto compartido usando la clave privada DH y la clave pública DH

    Implementación real de Diffie-Hellman
    """
    # Convertir la clave pública de string a bytes si es necesario
    if isinstance(public_key_pem_str, str):
        public_key_pem = public_key_pem_str.encode()
    else:
        public_key_pem = public_key_pem_str

    # Cargar las claves
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    # Calcular el secreto compartido
    shared_key = private_key.exchange(public_key)

    # Derivar una clave criptográfica del secreto compartido
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    shared_secret = digest.finalize()

    return shared_secret


def hash_password(password):
    """Hashea una contraseña usando bcrypt"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password, hashed_password):
    """Verifica una contraseña contra su hash"""
    plain_password_bytes = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)


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


def encrypt_message_aes(message, key):
    """Cifra un mensaje usando AES-CBC con la clave proporcionada"""
    # Asegurar que la clave tenga el tamaño correcto para AES
    if len(key) < 32:  # AES-256 necesita 32 bytes
        key = key + b'\0' * (32 - len(key))
    key = key[:32]

    # Generar un IV aleatorio
    iv = os.urandom(16)

    # Aplicar padding al mensaje
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Cifrar el mensaje
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combinar IV y ciphertext y codificar en base64
    encrypted_message = base64.b64encode(iv + ciphertext).decode()

    return encrypted_message


def decrypt_message_aes(encrypted_message, key):
    """Descifra un mensaje usando AES-CBC con la clave proporcionada"""
    # Asegurar que la clave tenga el tamaño correcto para AES
    if len(key) < 32:  # AES-256 necesita 32 bytes
        key = key + b'\0' * (32 - len(key))
    key = key[:32]

    # Decodificar el mensaje cifrado
    encrypted_data = base64.b64decode(encrypted_message)

    # Extraer IV y ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Descifrar el mensaje
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Quitar el padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode()

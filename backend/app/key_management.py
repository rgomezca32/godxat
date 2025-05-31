import os
import uuid
import base64
import hmac
import hashlib
import zipfile
import shutil
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from security import (
    generate_ephemeral_dh_keys,
    generate_shared_secret,
    sign_data_with_rsa,
    verify_signature_with_rsa
)

# Directorio para almacenar las claves privadas
BACKUP_DIR = os.path.join(os.path.expanduser("~"), ".secure_chat_keys")
# Directorio para almacenar claves compartidas entre usuarios en el mismo dispositivo
SHARED_DIR = os.path.join(os.path.expanduser("~"), ".secure_chat_shared")


def ensure_backup_dir(username):
    """Asegura que exista el directorio de respaldo para el usuario"""
    user_dir = os.path.join(BACKUP_DIR, username)
    sessions_dir = os.path.join(user_dir, "sessions")

    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(sessions_dir, exist_ok=True)

    # Asegurar que exista el directorio compartido
    os.makedirs(SHARED_DIR, exist_ok=True)

    return user_dir


def export_private_key(username, rsa_private, dh_private):
    """Exporta las claves privadas al dispositivo local"""
    user_dir = ensure_backup_dir(username)

    # Guardar clave RSA privada
    rsa_path = os.path.join(user_dir, "rsa_private.pem")
    with open(rsa_path, "wb") as f:
        f.write(rsa_private)

    # Guardar clave DH privada
    dh_path = os.path.join(user_dir, "dh_private.pem")
    with open(dh_path, "wb") as f:
        f.write(dh_private)

    return {"rsa_path": rsa_path, "dh_path": dh_path}


def load_private_key(username):
    """Carga las claves privadas desde el dispositivo local"""
    user_dir = os.path.join(BACKUP_DIR, username)

    rsa_path = os.path.join(user_dir, "rsa_private.pem")
    dh_path = os.path.join(user_dir, "dh_private.pem")

    if not os.path.exists(rsa_path) or not os.path.exists(dh_path):
        return None, None

    with open(rsa_path, "rb") as f:
        rsa_private = f.read()

    with open(dh_path, "rb") as f:
        dh_private = f.read()

    return rsa_private, dh_private


# Funciones para el manejo de claves efímeras

def store_ephemeral_keys(username, session_id, role, ephemeral_private, peer_ephemeral_public=None, peer_signature=None,
                         peer_rsa_public=None):
    """
    Almacena las claves efímeras para una sesión

    Args:
        username: Nombre del usuario
        session_id: ID de la sesión
        role: "initiator" o "receiver"
        ephemeral_private: Clave DH privada efímera del usuario
        peer_ephemeral_public: Clave DH pública efímera del otro usuario (opcional)
        peer_signature: Firma RSA de la clave DH pública del otro usuario (opcional)
        peer_rsa_public: Clave RSA pública del otro usuario (opcional)
    """
    user_dir = ensure_backup_dir(username)
    session_dir = os.path.join(user_dir, "sessions", session_id)
    os.makedirs(session_dir, exist_ok=True)

    # Guardar clave DH privada efímera
    with open(os.path.join(session_dir, "ephemeral_private.pem"), "wb") as f:
        f.write(ephemeral_private)

    # Guardar clave DH pública efímera del otro usuario si se proporciona
    if peer_ephemeral_public:
        with open(os.path.join(session_dir, "peer_ephemeral_public.pem"), "wb") as f:
            if isinstance(peer_ephemeral_public, str):
                f.write(peer_ephemeral_public.encode())
            else:
                f.write(peer_ephemeral_public)

    # Guardar firma de la clave DH pública del otro usuario si se proporciona
    if peer_signature:
        with open(os.path.join(session_dir, "peer_signature.txt"), "w") as f:
            f.write(peer_signature)

    # Guardar clave RSA pública del otro usuario si se proporciona
    if peer_rsa_public:
        with open(os.path.join(session_dir, "peer_rsa_public.pem"), "w") as f:
            f.write(peer_rsa_public)

    # Guardar el rol en la sesión
    with open(os.path.join(session_dir, "role.txt"), "w") as f:
        f.write(role)

    # Guardar una copia en el directorio compartido para permitir acceso entre usuarios
    shared_session_dir = os.path.join(SHARED_DIR, session_id)
    os.makedirs(shared_session_dir, exist_ok=True)

    # Guardar información sobre el usuario y su rol
    user_role_file = os.path.join(shared_session_dir, f"{username}_role.txt")
    with open(user_role_file, "w") as f:
        f.write(role)

    # Guardar la clave privada efímera (solo accesible por este usuario)
    user_private_file = os.path.join(shared_session_dir, f"{username}_ephemeral_private.pem")
    with open(user_private_file, "wb") as f:
        f.write(ephemeral_private)

    # Si hay clave pública del par, guardarla en el directorio compartido
    if peer_ephemeral_public:
        if role == "initiator":
            peer_public_file = os.path.join(shared_session_dir, "receiver_ephemeral_public.pem")
        else:
            peer_public_file = os.path.join(shared_session_dir, "initiator_ephemeral_public.pem")

        with open(peer_public_file, "wb") as f:
            if isinstance(peer_ephemeral_public, str):
                f.write(peer_ephemeral_public.encode())
            else:
                f.write(peer_ephemeral_public)

    # Si hay firma del par, guardarla en el directorio compartido
    if peer_signature:
        if role == "initiator":
            peer_sig_file = os.path.join(shared_session_dir, "receiver_signature.txt")
        else:
            peer_sig_file = os.path.join(shared_session_dir, "initiator_signature.txt")

        with open(peer_sig_file, "w") as f:
            f.write(peer_signature)

    # Si hay clave RSA pública del par, guardarla en el directorio compartido
    if peer_rsa_public:
        if role == "initiator":
            peer_rsa_file = os.path.join(shared_session_dir, "receiver_rsa_public.pem")
        else:
            peer_rsa_file = os.path.join(shared_session_dir, "initiator_rsa_public.pem")

        with open(peer_rsa_file, "w") as f:
            f.write(peer_rsa_public)

    return session_dir


def load_ephemeral_keys(username, session_id):
    """
    Carga las claves efímeras para una sesión

    Args:
        username: Nombre del usuario
        session_id: ID de la sesión

    Returns:
        ephemeral_private: Clave DH privada efímera del usuario
        peer_ephemeral_public: Clave DH pública efímera del otro usuario
        role: "initiator" o "receiver"
        peer_signature: Firma RSA de la clave DH pública del otro usuario
        peer_rsa_public: Clave RSA pública del otro usuario
    """
    # Primero intentar cargar desde el directorio del usuario
    user_dir = ensure_backup_dir(username)
    session_dir = os.path.join(user_dir, "sessions", session_id)

    ephemeral_private_path = os.path.join(session_dir, "ephemeral_private.pem")
    peer_ephemeral_public_path = os.path.join(session_dir, "peer_ephemeral_public.pem")
    role_path = os.path.join(session_dir, "role.txt")
    peer_signature_path = os.path.join(session_dir, "peer_signature.txt")
    peer_rsa_public_path = os.path.join(session_dir, "peer_rsa_public.pem")

    # Si no existe el directorio de sesión o la clave privada, intentar recuperar del directorio compartido
    if not os.path.exists(ephemeral_private_path):
        shared_session_dir = os.path.join(SHARED_DIR, session_id)
        if os.path.exists(shared_session_dir):
            # Verificar si existe información del usuario en el directorio compartido
            user_role_file = os.path.join(shared_session_dir, f"{username}_role.txt")
            user_private_file = os.path.join(shared_session_dir, f"{username}_ephemeral_private.pem")

            if os.path.exists(user_role_file) and os.path.exists(user_private_file):
                # Reconstruir el directorio de sesión del usuario
                os.makedirs(session_dir, exist_ok=True)

                # Copiar la clave privada
                shutil.copy2(user_private_file, ephemeral_private_path)

                # Leer el rol
                with open(user_role_file, "r") as f:
                    role = f.read().strip()

                # Guardar el rol
                with open(role_path, "w") as f:
                    f.write(role)

                # Determinar qué archivos del par necesitamos
                if role == "initiator":
                    peer_public_file = os.path.join(shared_session_dir, "receiver_ephemeral_public.pem")
                    peer_sig_file = os.path.join(shared_session_dir, "receiver_signature.txt")
                    peer_rsa_file = os.path.join(shared_session_dir, "receiver_rsa_public.pem")
                else:
                    peer_public_file = os.path.join(shared_session_dir, "initiator_ephemeral_public.pem")
                    peer_sig_file = os.path.join(shared_session_dir, "initiator_signature.txt")
                    peer_rsa_file = os.path.join(shared_session_dir, "initiator_rsa_public.pem")

                # Si existe la clave pública del par, copiarla
                if os.path.exists(peer_public_file):
                    shutil.copy2(peer_public_file, peer_ephemeral_public_path)

                # Si existe la firma del par, copiarla
                if os.path.exists(peer_sig_file):
                    shutil.copy2(peer_sig_file, peer_signature_path)

                # Si existe la clave RSA pública del par, copiarla
                if os.path.exists(peer_rsa_file):
                    shutil.copy2(peer_rsa_file, peer_rsa_public_path)

    # Ahora intentar cargar las claves
    if not os.path.exists(ephemeral_private_path):
        return None, None, None, None, None

    with open(ephemeral_private_path, "rb") as f:
        ephemeral_private = f.read()

    peer_ephemeral_public = None
    if os.path.exists(peer_ephemeral_public_path):
        with open(peer_ephemeral_public_path, "rb") as f:
            peer_ephemeral_public = f.read()

    role = "unknown"
    if os.path.exists(role_path):
        with open(role_path, "r") as f:
            role = f.read().strip()

    peer_signature = None
    if os.path.exists(peer_signature_path):
        with open(peer_signature_path, "r") as f:
            peer_signature = f.read().strip()

    peer_rsa_public = None
    if os.path.exists(peer_rsa_public_path):
        with open(peer_rsa_public_path, "r") as f:
            peer_rsa_public = f.read().strip()

    return ephemeral_private, peer_ephemeral_public, role, peer_signature, peer_rsa_public


def calculate_shared_secret(username, session_id, ephemeral_private, peer_ephemeral_public):
    """
    Calcula y almacena el secreto compartido usando claves efímeras

    Args:
        username: Nombre del usuario
        session_id: ID de la sesión
        ephemeral_private: Clave DH privada efímera del usuario
        peer_ephemeral_public: Clave DH pública efímera del otro usuario

    Returns:
        shared_secret: Secreto compartido calculado
    """
    # Calcular el secreto compartido
    shared_secret = generate_shared_secret(ephemeral_private, peer_ephemeral_public)

    # Derivar la clave raíz
    root_key = derive_root_key(shared_secret)

    # Derivar la clave de cadena
    chain_key = derive_chain_key(root_key)

    # Almacenar las claves en el directorio del usuario
    user_dir = ensure_backup_dir(username)
    session_dir = os.path.join(user_dir, "sessions", session_id)
    os.makedirs(os.path.join(session_dir, "message_keys"), exist_ok=True)

    with open(os.path.join(session_dir, "shared_secret.bin"), "wb") as f:
        f.write(shared_secret)

    with open(os.path.join(session_dir, "root_key.bin"), "wb") as f:
        f.write(root_key)

    with open(os.path.join(session_dir, "chain_key.bin"), "wb") as f:
        f.write(chain_key)

    # Almacenar también en el directorio compartido
    shared_session_dir = os.path.join(SHARED_DIR, session_id)
    os.makedirs(shared_session_dir, exist_ok=True)

    # Guardar el secreto compartido y las claves derivadas en el directorio compartido
    with open(os.path.join(shared_session_dir, "shared_secret.bin"), "wb") as f:
        f.write(shared_secret)

    with open(os.path.join(shared_session_dir, "root_key.bin"), "wb") as f:
        f.write(root_key)

    with open(os.path.join(shared_session_dir, "chain_key.bin"), "wb") as f:
        f.write(chain_key)

    # Crear directorio para claves de mensaje compartidas
    os.makedirs(os.path.join(shared_session_dir, "message_keys"), exist_ok=True)

    return shared_secret


def initiate_session(username, initiator_id, receiver_id):
    """
    Inicia una nueva sesión con claves DH efímeras (paso 1 del protocolo)

    Args:
        username: Nombre del usuario iniciador
        initiator_id: ID del usuario iniciador
        receiver_id: ID del usuario receptor

    Returns:
        session_id: Identificador único de la sesión
        ephemeral_public: Clave DH pública efímera del iniciador
        ephemeral_private: Clave DH privada efímera del iniciador
        signature: Firma RSA de la clave DH pública
    """
    # Generar un identificador único para la sesión
    session_id = str(uuid.uuid4())

    # Generar un nuevo par de claves DH efímeras
    ephemeral_public, ephemeral_private = generate_ephemeral_dh_keys()

    # Cargar la clave RSA privada del usuario para firmar
    rsa_private, _ = load_private_key(username)
    if not rsa_private:
        raise ValueError("No se encontró la clave RSA privada del usuario")

    # Firmar la clave DH pública con la clave RSA privada
    signature = sign_data_with_rsa(ephemeral_public, rsa_private)

    # Almacenar la clave privada efímera localmente
    store_ephemeral_keys(username, session_id, "initiator", ephemeral_private)

    # Guardar la clave pública en el directorio compartido
    shared_session_dir = os.path.join(SHARED_DIR, session_id)
    os.makedirs(shared_session_dir, exist_ok=True)

    with open(os.path.join(shared_session_dir, "initiator_ephemeral_public.pem"), "wb") as f:
        f.write(ephemeral_public.encode() if isinstance(ephemeral_public, str) else ephemeral_public)

    return session_id, ephemeral_public, ephemeral_private, signature


def accept_session(username, session_id, initiator_ephemeral_public, initiator_signature, initiator_rsa_public):
    """
    Acepta una sesión pendiente y genera claves DH efímeras (paso 2 del protocolo)

    Args:
        username: Nombre del usuario receptor
        session_id: ID de la sesión
        initiator_ephemeral_public: Clave DH pública efímera del iniciador
        initiator_signature: Firma RSA de la clave DH pública del iniciador
        initiator_rsa_public: Clave RSA pública del iniciador

    Returns:
        ephemeral_public: Clave DH pública efímera del receptor
        shared_secret: Secreto compartido calculado
        signature: Firma RSA de la clave DH pública del receptor
    """
    # Verificar la firma de la clave DH pública del iniciador
    if not verify_signature_with_rsa(initiator_ephemeral_public, initiator_signature, initiator_rsa_public):
        raise ValueError("La firma de la clave DH pública del iniciador no es válida")

    # Generar un nuevo par de claves DH efímeras
    ephemeral_public, ephemeral_private = generate_ephemeral_dh_keys()

    # Cargar la clave RSA privada del usuario para firmar
    rsa_private, _ = load_private_key(username)
    if not rsa_private:
        raise ValueError("No se encontró la clave RSA privada del usuario")

    # Firmar la clave DH pública con la clave RSA privada
    signature = sign_data_with_rsa(ephemeral_public, rsa_private)

    # Almacenar las claves efímeras localmente
    store_ephemeral_keys(
        username,
        session_id,
        "receiver",
        ephemeral_private,
        initiator_ephemeral_public,
        initiator_signature,
        initiator_rsa_public
    )

    # Guardar la clave pública del receptor en el directorio compartido
    shared_session_dir = os.path.join(SHARED_DIR, session_id)
    os.makedirs(shared_session_dir, exist_ok=True)

    with open(os.path.join(shared_session_dir, "receiver_ephemeral_public.pem"), "wb") as f:
        f.write(ephemeral_public.encode() if isinstance(ephemeral_public, str) else ephemeral_public)

    # Calcular el secreto compartido
    shared_secret = calculate_shared_secret(
        username,
        session_id,
        ephemeral_private,
        initiator_ephemeral_public
    )

    return ephemeral_public, shared_secret, signature


def complete_session(username, session_id, receiver_ephemeral_public, receiver_signature, receiver_rsa_public):
    """
    Completa el establecimiento de sesión para el iniciador (paso 3 del protocolo)

    Args:
        username: Nombre del usuario iniciador
        session_id: ID de la sesión
        receiver_ephemeral_public: Clave DH pública efímera del receptor
        receiver_signature: Firma RSA de la clave DH pública del receptor
        receiver_rsa_public: Clave RSA pública del receptor

    Returns:
        shared_secret: Secreto compartido calculado
    """
    # Verificar la firma de la clave DH pública del receptor
    if not verify_signature_with_rsa(receiver_ephemeral_public, receiver_signature, receiver_rsa_public):
        raise ValueError("La firma de la clave DH pública del receptor no es válida")

    # Cargar la clave privada efímera del iniciador
    ephemeral_private, _, role, _, _ = load_ephemeral_keys(username, session_id)

    if not ephemeral_private or role != "initiator":
        raise ValueError("No se encontró la clave privada efímera del iniciador para esta sesión")

    # Almacenar la clave pública efímera del receptor y su firma
    store_ephemeral_keys(
        username,
        session_id,
        "initiator",
        ephemeral_private,
        receiver_ephemeral_public,
        receiver_signature,
        receiver_rsa_public
    )

    # Calcular el secreto compartido
    shared_secret = calculate_shared_secret(
        username,
        session_id,
        ephemeral_private,
        receiver_ephemeral_public
    )

    return shared_secret


def derive_root_key(shared_secret):
    """Deriva una clave raíz a partir del secreto compartido"""
    return hmac.new(shared_secret, b"root_key", hashlib.sha256).digest()


def derive_chain_key(root_key):
    """Deriva una clave de cadena a partir de la clave raíz"""
    return hmac.new(root_key, b"chain_key", hashlib.sha256).digest()


def derive_message_key(username, session_id, message_number):
    """
    Deriva una clave de mensaje a partir de la clave de cadena.

    Args:
        username: Nombre del usuario
        session_id: ID de la sesión
        message_number: Número secuencial del mensaje

    Returns:
        message_key: Clave para cifrar/descifrar el mensaje
    """
    user_dir = ensure_backup_dir(username)
    session_dir = os.path.join(user_dir, "sessions", session_id)
    shared_session_dir = os.path.join(SHARED_DIR, session_id)

    # Verificar si la clave de mensaje ya existe en el directorio del usuario
    message_key_path = os.path.join(session_dir, "message_keys", f"{message_number}.bin")
    if os.path.exists(message_key_path):
        with open(message_key_path, "rb") as f:
            return f.read()

    # Verificar si la clave de mensaje existe en el directorio compartido
    shared_message_key_path = os.path.join(shared_session_dir, "message_keys", f"{message_number}.bin")
    if os.path.exists(shared_message_key_path):
        # Copiar la clave al directorio del usuario
        os.makedirs(os.path.join(session_dir, "message_keys"), exist_ok=True)
        shutil.copy2(shared_message_key_path, message_key_path)
        with open(message_key_path, "rb") as f:
            return f.read()

    # Cargar la clave de cadena actual
    chain_key_path = os.path.join(session_dir, "chain_key.bin")
    shared_chain_key_path = os.path.join(shared_session_dir, "chain_key.bin")

    # Si no existe la clave de cadena en el directorio del usuario pero sí en el compartido, copiarla
    if not os.path.exists(chain_key_path) and os.path.exists(shared_chain_key_path):
        shutil.copy2(shared_chain_key_path, chain_key_path)

    if not os.path.exists(chain_key_path):
        raise FileNotFoundError(f"No se encontró la clave de cadena para la sesión {session_id}")

    with open(chain_key_path, "rb") as f:
        chain_key = f.read()

    # Derivar la clave de mensaje
    message_key = hmac.new(chain_key, b"message_key", hashlib.sha256).digest()

    # Actualizar la clave de cadena
    new_chain_key = hmac.new(chain_key, b"chain_key", hashlib.sha256).digest()

    # Guardar la nueva clave de cadena en el directorio del usuario
    with open(chain_key_path, "wb") as f:
        f.write(new_chain_key)

    # Guardar la nueva clave de cadena en el directorio compartido
    with open(shared_chain_key_path, "wb") as f:
        f.write(new_chain_key)

    # Guardar la clave de mensaje en el directorio del usuario
    os.makedirs(os.path.join(session_dir, "message_keys"), exist_ok=True)
    with open(message_key_path, "wb") as f:
        f.write(message_key)

    # Guardar la clave de mensaje en el directorio compartido
    os.makedirs(os.path.join(shared_session_dir, "message_keys"), exist_ok=True)
    with open(shared_message_key_path, "wb") as f:
        f.write(message_key)

    return message_key


def perform_dh_ratchet(username, session_id, new_peer_ephemeral_public, new_peer_signature, new_peer_rsa_public):
    """
    Realiza una rotación DH para actualizar las claves de la sesión.

    Args:
        username: Nombre del usuario
        session_id: ID de la sesión
        new_peer_ephemeral_public: Nueva clave DH pública efímera del otro usuario
        new_peer_signature: Firma RSA de la nueva clave DH pública del otro usuario
        new_peer_rsa_public: Clave RSA pública del otro usuario
    """
    # Verificar la firma de la nueva clave DH pública
    if not verify_signature_with_rsa(new_peer_ephemeral_public, new_peer_signature, new_peer_rsa_public):
        raise ValueError("La firma de la nueva clave DH pública no es válida")

    # Generar un nuevo par de claves DH efímeras
    new_ephemeral_public, new_ephemeral_private = generate_ephemeral_dh_keys()

    # Cargar la clave RSA privada del usuario para firmar
    rsa_private, _ = load_private_key(username)
    if not rsa_private:
        raise ValueError("No se encontró la clave RSA privada del usuario")

    # Firmar la nueva clave DH pública con la clave RSA privada
    signature = sign_data_with_rsa(new_ephemeral_public, rsa_private)

    # Cargar el rol del usuario en esta sesión
    _, _, role, _, _ = load_ephemeral_keys(username, session_id)

    # Almacenar la nueva clave privada efímera y la nueva clave pública del otro usuario
    store_ephemeral_keys(
        username,
        session_id,
        role,
        new_ephemeral_private,
        new_peer_ephemeral_public,
        new_peer_signature,
        new_peer_rsa_public
    )

    # Calcular el nuevo secreto compartido
    calculate_shared_secret(username, session_id, new_ephemeral_private, new_peer_ephemeral_public)

    return new_ephemeral_public, signature


def encrypt_message_with_session(message, username, session_id, message_number, rsa_private=None):
    """
    Cifra un mensaje usando la clave de mensaje derivada de la sesión y lo firma con RSA.

    Args:
        message: Mensaje en texto plano
        username: Nombre del usuario
        session_id: ID de la sesión
        message_number: Número secuencial del mensaje
        rsa_private: Clave RSA privada para firmar (opcional, se cargará si no se proporciona)

    Returns:
        encrypted_message: Mensaje cifrado y firmado en formato JSON
    """
    # Derivar la clave de mensaje
    message_key = derive_message_key(username, session_id, message_number)

    # Generar un IV aleatorio
    iv = os.urandom(16)

    # Cifrar el mensaje con AES-CBC
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(message_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combinar IV y ciphertext
    encrypted_data = iv + ciphertext
    encrypted_base64 = base64.b64encode(encrypted_data).decode()

    # Cargar la clave RSA privada si no se proporcionó
    if not rsa_private:
        rsa_private, _ = load_private_key(username)
        if not rsa_private:
            raise ValueError("No se encontró la clave RSA privada del usuario")

    # Firmar el mensaje cifrado
    signature = sign_data_with_rsa(encrypted_base64, rsa_private)

    # Crear un objeto JSON con el mensaje cifrado y la firma
    encrypted_message = {
        "encrypted_data": encrypted_base64,
        "signature": signature,
        "message_number": message_number
    }

    return json.dumps(encrypted_message)


def decrypt_message_with_session(encrypted_message_json, username, session_id, sender_rsa_public):
    """
    Descifra un mensaje usando la clave de mensaje derivada de la sesión y verifica la firma RSA.

    Args:
        encrypted_message_json: Mensaje cifrado y firmado en formato JSON
        username: Nombre del usuario
        session_id: ID de la sesión
        sender_rsa_public: Clave RSA pública del remitente

    Returns:
        decrypted_message: Mensaje en texto plano
    """
    try:
        # Parsear el JSON
        message_data = json.loads(encrypted_message_json)
        encrypted_base64 = message_data["encrypted_data"]
        signature = message_data["signature"]
        message_number = message_data["message_number"]

        # Verificar la firma del mensaje cifrado
        if not verify_signature_with_rsa(encrypted_base64, signature, sender_rsa_public):
            raise ValueError("La firma del mensaje no es válida")

        # Decodificar el mensaje cifrado
        encrypted_data = base64.b64decode(encrypted_base64)

        # Extraer IV y ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Derivar la clave de mensaje
        message_key = derive_message_key(username, session_id, message_number)

        # Descifrar el mensaje
        cipher = Cipher(algorithms.AES(message_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Quitar el padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode()
    except Exception as e:
        # Si hay un error al descifrar, probablemente es porque no tenemos la clave correcta
        # (mensaje recibido en otro dispositivo)
        raise ValueError(f"No se pudo descifrar el mensaje: {str(e)}")


def export_sessions(username):
    """
    Exporta todas las sesiones del usuario para respaldo.

    Args:
        username: Nombre del usuario

    Returns:
        backup_file: Ruta del archivo de respaldo
    """
    user_dir = ensure_backup_dir(username)
    sessions_dir = os.path.join(user_dir, "sessions")

    if not os.path.exists(sessions_dir) or not os.listdir(sessions_dir):
        return None

    # Crear un archivo ZIP con todas las sesiones
    backup_file = os.path.join(user_dir, f"{username}_sessions_backup.zip")
    with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(sessions_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, user_dir)
                zipf.write(file_path, arcname)

    return backup_file


def import_sessions(username, backup_file):
    """
    Importa sesiones desde un archivo de respaldo.

    Args:
        username: Nombre del usuario
        backup_file: Ruta del archivo de respaldo

    Returns:
        success: True si la importación fue exitosa, False en caso contrario
    """
    user_dir = ensure_backup_dir(username)

    if not os.path.exists(backup_file):
        return False

    # Extraer el archivo ZIP
    try:
        with zipfile.ZipFile(backup_file, 'r') as zipf:
            zipf.extractall(user_dir)
        return True
    except Exception:
        return False

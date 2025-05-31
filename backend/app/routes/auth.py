from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, Message, KeySession
from schemas import UserCreate, UserLogin, MessageCreate
from security import generate_rsa_keys, generate_dh_keys, hash_password, create_access_token, verify_password, \
    SECRET_KEY, ALGORITHM, sign_data_with_rsa, verify_signature_with_rsa
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional, List
from key_management import (
    export_private_key, load_private_key, BACKUP_DIR,
    initiate_session, accept_session, complete_session,
    encrypt_message_with_session, decrypt_message_with_session,
    export_sessions, import_sessions, load_ephemeral_keys
)
from fastapi.security import OAuth2PasswordBearer
import os
import uuid

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")
router = APIRouter()

failed_attempts = {} # Estructura que guarda la IP/Usuario si esta bloqueado
MAX_ATTEMPTS = 5  # Cantidad máxima de intentos por IP/Usuario
BLOCK_TIME_MINUTES = 1 # Cantidad de minutos hasta reintentar el login

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


@router.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Verificamos si el usuario ya existe
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya está registrado."
        )

    rsa_pub, rsa_priv = generate_rsa_keys()
    dh_pub, dh_priv = generate_dh_keys()

    # Hasheamos la contraseña con bcrypt
    password_hash = hash_password(user.password)

    new_user = User(
        username=user.username,
        password_hash=password_hash,
        rsa_public_key=rsa_pub,
        dh_public_key=dh_pub
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Guardamos claves privadas en el dispositivo del usuario
    export_private_key(user.username, rsa_priv, dh_priv)

    return {"message": "Usuario registrado correctamente"}


@router.post("/login/")
def login(request: Request, user: UserLogin, db: Session = Depends(get_db)):

    db_user = db.query(User).filter(User.username == user.username).first()

    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales invalidas ")

    access_token = create_access_token(
        data={"sub": db_user.username},
        expires_delta=timedelta(minutes=30)
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.delete("/delete_user/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    # Buscamos el usuario en la base de datos SQL
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Eliminamos todos los mensajes asociados a este usuario
    db.query(Message).filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).delete()

    # Eliminamos todas las sesiones asociadas a este usuario
    db.query(KeySession).filter(
        (KeySession.initiator_id == user_id) | (KeySession.receiver_id == user_id)
    ).delete()

    # Eliminamos el usuario de la base de datos SQL
    db.delete(user)
    db.commit()

    # Eliminamos las claves privadas del usuario en el dispositivo local
    user_dir = os.path.join(BACKUP_DIR, user.username)
    if os.path.exists(user_dir):
        import shutil
        shutil.rmtree(user_dir)

    return {"message": "Usuario, mensajes y sesiones eliminados, claves privadas borradas"}


@router.get("/get_user/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "rsa_public_key": current_user.rsa_public_key,
        "dh_public_key": current_user.dh_public_key
    }


@router.get("/get_user/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    # Buscamos el usuario en la base de datos SQL
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {
        "id": user.id,
        "username": user.username,
        "rsa_public_key": user.rsa_public_key,
        "dh_public_key": user.dh_public_key,
    }


@router.get("/get_all_users")
def get_all_users(db: Session = Depends(get_db)):
    # Obtenemos todos los usuarios de la base de datos SQL
    users = db.query(User).all()

    # Convertimos la lista de usuarios a un formato legible JSON
    return [
        {
            "id": user.id,
            "username": user.username,
            "rsa_public_key": user.rsa_public_key,
            "dh_public_key": user.dh_public_key,
        }
        for user in users
    ]


@router.get("/search_user/{name}")
def search_user(name: str, db: Session = Depends(get_db)):
    users = db.query(User).filter(User.username.ilike(f"%{name}%")).limit(10).all()
    return {"users": [{"id": u.id, "username": u.username} for u in users]}


# Nuevos endpoints para el intercambio de claves DH efímeras

@router.post("/initiate_session/{receiver_id}")
def initiate_session_endpoint(
        receiver_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Inicia una nueva sesión con claves DH efímeras (paso 1 del protocolo)"""
    # Verificar que el receptor existe
    receiver = db.query(User).filter(User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receptor no encontrado")

    # Verificar si ya existe una sesión pendiente o activa entre estos usuarios
    existing_session = db.query(KeySession).filter(
        (
                ((KeySession.initiator_id == current_user.id) & (KeySession.receiver_id == receiver_id)) |
                ((KeySession.initiator_id == receiver_id) & (KeySession.receiver_id == current_user.id))
        ),
        KeySession.status.in_(["pending", "active"])
    ).first()

    if existing_session:
        if existing_session.status == "active":
            raise HTTPException(
                status_code=400,
                detail="Ya existe una sesión activa con este usuario"
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="Ya existe una solicitud de sesión pendiente con este usuario"
            )

    # Cargar la clave RSA privada para firmar
    rsa_private, _ = load_private_key(current_user.username)
    if not rsa_private:
        raise HTTPException(status_code=500, detail="No se encontró la clave RSA privada del usuario")

    # Iniciar sesión con claves DH efímeras y firmar la clave pública
    session_id, ephemeral_public, _, signature = initiate_session(
        current_user.username,
        current_user.id,
        receiver_id
    )

    # Crear sesión pendiente en la base de datos
    new_session = KeySession(
        session_id=session_id,
        initiator_id=current_user.id,
        receiver_id=receiver_id,
        initiator_ephemeral_public=ephemeral_public,
        initiator_signature=signature,
        initiator_rsa_public=current_user.rsa_public_key,
        status="pending",
    )
    db.add(new_session)
    db.commit()

    return {
        "session_id": session_id,
        "status": "pending",
        "message": "Sesión iniciada, esperando aceptación del receptor"
    }


@router.get("/pending_sessions/")
def get_pending_sessions(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene todas las sesiones pendientes donde el usuario es el receptor"""
    pending_sessions = db.query(KeySession).filter(
        KeySession.receiver_id == current_user.id,
        KeySession.status == "pending"
    ).all()

    return {
        "pending_sessions": [
            {
                "session_id": session.session_id,
                "initiator_id": session.initiator_id,
                "initiator_username": db.query(User).filter(User.id == session.initiator_id).first().username,
                "created_at": session.created_at.isoformat()
            }
            for session in pending_sessions
        ]
    }


@router.post("/accept_session/{session_id}")
def accept_session_endpoint(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Acepta una sesión pendiente y envía clave DH pública efímera (paso 2 del protocolo)"""
    # Verificar que la sesión existe y está pendiente
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.receiver_id == current_user.id,
        KeySession.status == "pending"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión pendiente no encontrada")

    # Verificar la firma de la clave DH pública del iniciador
    if not verify_signature_with_rsa(
            session.initiator_ephemeral_public,
            session.initiator_signature,
            session.initiator_rsa_public
    ):
        raise HTTPException(
            status_code=400,
            detail="La firma de la clave DH pública del iniciador no es válida"
        )

    # Cargar la clave RSA privada para firmar
    rsa_private, _ = load_private_key(current_user.username)
    if not rsa_private:
        raise HTTPException(status_code=500, detail="No se encontró la clave RSA privada del usuario")

    # Aceptar la sesión, generar claves DH efímeras y firmarlas
    ephemeral_public, _, signature = accept_session(
        current_user.username,
        session_id,
        session.initiator_ephemeral_public,
        session.initiator_signature,
        session.initiator_rsa_public
    )

    # Actualizar sesión a estado "active" en la base de datos
    session.receiver_ephemeral_public = ephemeral_public
    session.receiver_signature = signature
    session.receiver_rsa_public = current_user.rsa_public_key
    session.status = "active"
    session.updated_at = datetime.utcnow()
    db.commit()

    return {
        "session_id": session_id,
        "status": "active",
        "message": "Sesión aceptada correctamente"
    }


@router.post("/reject_session/{session_id}")
def reject_session_endpoint(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Rechaza una sesión pendiente"""
    # Verificar que la sesión existe y está pendiente
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.receiver_id == current_user.id,
        KeySession.status == "pending"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión pendiente no encontrada")

    # Eliminar la sesión de la base de datos
    db.delete(session)
    db.commit()

    # Eliminar archivos de claves locales si existen
    try:
        session_dir = os.path.join(
            BACKUP_DIR,
            current_user.username,
            "sessions",
            session_id
        )
        if os.path.exists(session_dir):
            import shutil
            shutil.rmtree(session_dir)

        # También eliminar del directorio compartido
        shared_dir = os.path.join(
            os.path.dirname(BACKUP_DIR),
            ".secure_chat_shared",
            session_id
        )
        if os.path.exists(shared_dir):
            import shutil
            shutil.rmtree(shared_dir)
    except Exception as e:
        # Log error but continue
        print(f"Error removing session files: {e}")

    return {
        "message": "Sesión rechazada correctamente"
    }


@router.post("/complete_session/{session_id}")
def complete_session_endpoint(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Completa el establecimiento de sesión para el iniciador (paso 3 del protocolo)"""
    # Verificar que la sesión existe y está activa
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.initiator_id == current_user.id,
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    # Verificar la firma de la clave DH pública del receptor
    if not verify_signature_with_rsa(
            session.receiver_ephemeral_public,
            session.receiver_signature,
            session.receiver_rsa_public
    ):
        raise HTTPException(
            status_code=400,
            detail="La firma de la clave DH pública del receptor no es válida"
        )

    # Completar el establecimiento de sesión
    try:
        complete_session(
            current_user.username,
            session_id,
            session.receiver_ephemeral_public,
            session.receiver_signature,
            session.receiver_rsa_public
        )

        return {
            "session_id": session_id,
            "status": "active",
            "message": "Establecimiento de sesión completado correctamente"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al completar la sesión: {str(e)}")


@router.get("/active_sessions/")
def get_active_sessions(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene todas las sesiones activas del usuario"""
    active_sessions = db.query(KeySession).filter(
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).all()

    return {
        "active_sessions": [
            {
                "session_id": session.session_id,
                "initiator_id": session.initiator_id,
                "receiver_id": session.receiver_id,
                "role": "initiator" if session.initiator_id == current_user.id else "receiver",
                "peer_id": session.receiver_id if session.initiator_id == current_user.id else session.initiator_id,
                "peer_username": db.query(User).filter(
                    User.id == (
                        session.receiver_id if session.initiator_id == current_user.id else session.initiator_id)
                ).first().username,
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat()
            }
            for session in active_sessions
        ]
    }


@router.post("/close_session/{session_id}")
def close_session(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Cierra una sesión activa"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    # Cerrar la sesión
    session.status = "closed"
    session.updated_at = datetime.utcnow()
    db.commit()

    return {
        "session_id": session_id,
        "status": "closed",
        "message": "Sesión cerrada correctamente"
    }


@router.delete("/delete_session/{session_id}")
def delete_session(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Elimina una sesión y todos sus mensajes asociados"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id))
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    # Obtener el ID del otro usuario
    peer_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id

    # Eliminar todos los mensajes asociados a esta sesión
    db.query(Message).filter(
        Message.session_id == session_id
    ).delete()

    # Eliminar la sesión
    db.delete(session)
    db.commit()

    # Eliminar archivos de claves locales si existen
    try:
        session_dir = os.path.join(
            BACKUP_DIR,
            current_user.username,
            "sessions",
            session_id
        )
        if os.path.exists(session_dir):
            import shutil
            shutil.rmtree(session_dir)

        # También eliminar del directorio compartido
        shared_dir = os.path.join(
            os.path.dirname(BACKUP_DIR),
            ".secure_chat_shared",
            session_id
        )
        if os.path.exists(shared_dir):
            import shutil
            shutil.rmtree(shared_dir)
    except Exception as e:
        # Log error but continue
        print(f"Error removing session files: {e}")

    return {
        "message": "Sesión y mensajes eliminados correctamente",
        "peer_id": peer_id
    }


@router.post("/export_sessions/")
def export_user_sessions(current_user: User = Depends(get_current_user)):
    """Exporta todas las sesiones del usuario para respaldo"""
    backup_file = export_sessions(current_user.username)
    if not backup_file:
        raise HTTPException(status_code=404, detail="No hay sesiones para exportar")

    return {"backup_file": backup_file}


@router.post("/import_sessions/")
def import_user_sessions(backup_file: str, current_user: User = Depends(get_current_user)):
    """Importa sesiones desde un archivo de respaldo"""
    success = import_sessions(current_user.username, backup_file)
    if not success:
        raise HTTPException(status_code=400, detail="Error al importar sesiones")

    return {"message": "Sesiones importadas correctamente"}

@router.get("/outgoing_pending_sessions/", response_model=dict)
def get_outgoing_pending_sessions(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # Obtener sesiones pendientes donde el usuario es el iniciador
    pending_sessions = db.query(KeySession).filter(
        KeySession.initiator_id == current_user.id,
        KeySession.status.in_(["pending", "accepted"])
    ).all()

    result = []

    for session in pending_sessions:
        receiver = db.query(User).filter(User.id == session.receiver_id).first()
        if receiver:
            result.append({
                "session_id": session.session_id,
                "receiver_id": receiver.id,
                "receiver_username": receiver.username,
                "status": session.status,
                "created_at": session.created_at.isoformat()
            })

    return {"pending_sessions": result}


@router.post("/cancel_session/{session_id}", response_model=dict)
def cancel_session(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # Buscar la sesión pendiente iniciada por el usuario
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.initiator_id == current_user.id,
        KeySession.status.in_(["pending", "accepted"])
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Pending session not found")

    # Eliminar la sesión
    db.delete(session)
    db.commit()

    # Eliminar archivos de claves locales
    try:
        session_dir = os.path.join(
            "keys",
            current_user.username,
            "sessions",
            session_id
        )
        if os.path.exists(session_dir):
            import shutil
            shutil.rmtree(session_dir)
    except Exception as e:
        # Log error but continue
        print(f"Error removing session files: {e}")

    return {
        "message": "Session cancelled successfully"
    }

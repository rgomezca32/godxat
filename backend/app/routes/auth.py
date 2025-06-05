from urllib import request

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from argon2 import PasswordHasher, exceptions
from sqlalchemy.orm import Session
from app.database import SessionLocal,redis_client,BLOCK_TIME_SECONDS,MAX_ATTEMPTS_LOGIN
from app.models import User, Message, KeySession
from app.schemas import UserCreate, UserLogin, MessageCreate
from app.security import create_access_token, verify_password, SECRET_KEY, ALGORITHM
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional, List
from fastapi.security import OAuth2PasswordBearer
import asyncio
from app.routes.websocket import notify_session_update
import os
import uuid

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")
router = APIRouter()
ph = PasswordHasher()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def check_login_attempts(ip: str, username: str):
    key = f"login_attempts:{ip}:{username}"
    attempts = redis_client.get(key)
    if attempts and int(attempts) >= MAX_ATTEMPTS_LOGIN:
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Inténtalo más tarde."
        )
    return key

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
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya está registrado."
        )
    password_hash = ph.hash(user.password)

    new_user = User(
        username=user.username,
        password_hash=password_hash,
        rsa_public_key=user.rsa_public_key,
        dh_public_key=user.dh_public_key
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "Usuario registrado correctamente"}


@router.post("/login/")
def login(user: UserLogin, request: Request,db: Session = Depends(get_db)):
    ip = request.client.host
    username = user.username
    redis_key = check_login_attempts(ip, username)

    db_user = db.query(User).filter(User.username == username).first()

    if not db_user:
        # Usuario no existe, incrementar contador y bloquear si hace falta
        redis_client.incr(redis_key)
        redis_client.expire(redis_key, BLOCK_TIME_SECONDS)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    try:
        # Verificar contraseña
        if not ph.verify(db_user.password_hash, user.password):
            # Contraseña incorrecta
            redis_client.incr(redis_key)
            redis_client.expire(redis_key, BLOCK_TIME_SECONDS)
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
    except Exception:
        # verify puede lanzar excepción si no coincide así evitamos errores
        redis_client.incr(redis_key)
        redis_client.expire(redis_key, BLOCK_TIME_SECONDS)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Resetear contador si el login es exitoso
    redis_client.delete(redis_key)

    if not db_user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")


    access_token = create_access_token(
        data={"sub": db_user.username},
        expires_delta=timedelta(minutes=30)
    )

    return {"token": access_token, "token_type": "bearer"}


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

    # Nota: Ya no eliminamos claves privadas del backend
    # Las claves privadas se almacenan exclusivamente en el frontend/Tauri

    return {"message": "Usuario, mensajes y sesiones eliminados"}


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


# Endpoints para el intercambio de claves DH efímeras
# Modificados para solo almacenar datos ya preparados por el frontend

@router.post("/initiate_session/{receiver_id}")
async def initiate_session_endpoint(
        receiver_id: int,
        session_data: dict,  # Contiene session_id, ephemeral_public, signature
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

    # Nota: Ya no generamos ni firmamos claves en el backend
    # El frontend envía la clave pública efímera y la firma ya generadas

    # Crear sesión pendiente en la base de datos con los datos recibidos del frontend
    new_session = KeySession(
        session_id=session_data["session_id"],
        initiator_id=current_user.id,
        receiver_id=receiver_id,
        initiator_ephemeral_public=session_data["ephemeral_public"],
        initiator_signature=session_data["signature"],
        initiator_rsa_public=current_user.rsa_public_key,
        status="pending",
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    # Notificar al receptor a través de WebSocket
    asyncio.create_task(notify_session_update(new_session, "session_request", db))

    return {
        "session_id": session_data["session_id"],
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
                "created_at": session.created_at.isoformat(),
                "initiator_ephemeral_public": session.initiator_ephemeral_public,
                "initiator_signature": session.initiator_signature,
                "initiator_rsa_public": session.initiator_rsa_public
            }
            for session in pending_sessions
        ]
    }

@router.get("/out_coming_pending_sessions/")
def get_out_coming_pending_sessions(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene todas las sesiones pendientes donde el usuario es el iniciador"""
    out_pending_sessions = db.query(KeySession).filter(
        KeySession.initiator_id == current_user.id,
        KeySession.status == "pending"
    ).all()

    return {
        "out_pending_sessions": [
            {
                "session_id": session.session_id,
                "receiver_id": session.receiver_id,
                "receiver_username": db.query(User).filter(User.id == session.receiver_id).first().username,
                "created_at": session.created_at.isoformat(),
                "initiator_ephemeral_public": session.initiator_ephemeral_public,
                "initiator_signature": session.initiator_signature,
                "initiator_rsa_public": session.initiator_rsa_public
            }
            for session in out_pending_sessions
        ]
    }


@router.post("/accept_session/{session_id}")
async def accept_session_endpoint(
        session_id: str,
        session_data: dict,  # Contiene ephemeral_public, signature
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

    # Nota: Ya no verificamos firmas en el backend
    # La verificación se realiza en el frontend

    # Nota: Ya no generamos ni firmamos claves en el backend
    # El frontend envía la clave pública efímera y la firma ya generadas

    # Actualizar sesión a estado "active" en la base de datos con los datos recibidos del frontend
    session.receiver_ephemeral_public = session_data["ephemeral_public"]
    session.receiver_signature = session_data["signature"]
    session.receiver_rsa_public = current_user.rsa_public_key
    session.status = "incomplete"
    session.updated_at = datetime.utcnow()
    db.commit()

    # Notificar al iniciador a través de WebSocket
    asyncio.create_task(notify_session_update(session, "session_accepted", db))

    return {
        "session_id": session_id,
        "status": "active",
        "message": "Sesión aceptada correctamente"
    }


@router.post("/reject_session/{session_id}")
async def reject_session_endpoint(
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

    # Guardar una copia de la sesión para notificación
    session_copy = KeySession(
        session_id=session.session_id,
        initiator_id=session.initiator_id,
        receiver_id=session.receiver_id,
        status="rejected"
    )

    # Eliminar la sesión de la base de datos
    db.delete(session)
    db.commit()

    # Notificar al iniciador a través de WebSocket
    asyncio.create_task(notify_session_update(session_copy, "session_rejected", db))

    return {
        "message": "Sesión rechazada correctamente"
    }

@router.post("/cancel_session/{session_id}")
def cancel_session_endpoint(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Cancela una sesión pendiente"""
    # Verificar que la sesión existe y está pendiente
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.initiator_id == current_user.id,
        KeySession.status == "pending"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión pendiente no encontrada")

    # Eliminar la sesión de la base de datos
    db.delete(session)
    db.commit()

    return {
        "message": "Sesión cancelada correctamente"
    }


@router.post("/complete_session/{session_id}")
async def complete_session_endpoint(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Completa el establecimiento de sesión para el iniciador (paso 3 del protocolo)"""
    # Verificar que la sesión existe y está incompleta
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.initiator_id == current_user.id,
        KeySession.status == "incomplete"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    session.status = "active"
    session.updated_at = datetime.utcnow()
    db.commit()

    # Notificar al receptor a través de WebSocket
    asyncio.create_task(notify_session_update(session, "session_completed", db))

    return {
        "session_id": session_id,
        "status": "active",
        "message": "Establecimiento de sesión completado correctamente"
    }

@router.get("/get_session/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    session = db.query(KeySession).filter(KeySession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    # Solo pueden verla el iniciador o el receptor
    if current_user.id not in [session.initiator_id, session.receiver_id]:
        raise HTTPException(status_code=403, detail="No autorizado")

    return {
        "session_id": session.session_id,
        "status": session.status,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "initiator_ephemeral_public": session.initiator_ephemeral_public,
        "receiver_ephemeral_public": session.receiver_ephemeral_public,
        "initiator_signature": session.initiator_signature,
        "receiver_signature": session.receiver_signature,
        "initiator_rsa_public": session.initiator_rsa_public,
        "receiver_rsa_public": session.receiver_rsa_public,
        "initiator": {
            "id": session.initiator.id,
            "username": session.initiator.username,
        },
        "receiver": {
            "id": session.receiver.id,
            "username": session.receiver.username,
        },
    }

@router.get("/incomplete_sessions/")
def get_incomplete_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Obtiene todas las sesiones incompletas iniciadas por el usuario actual"""
    incomplete_sessions = db.query(KeySession).filter(
        (KeySession.initiator_id == current_user.id),
        KeySession.status == "incomplete"
    ).all()

    return {
        "incomplete_sessions": [
            {
                "session_id": session.session_id,
                "initiator_id": session.initiator_id,
                "receiver_id": session.receiver_id,
                "role": "initiator",
                "peer_id": session.receiver_id,
                "peer_username": db.query(User).filter(User.id == session.receiver_id).first().username,
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat(),
                "initiator_ephemeral_public": session.initiator_ephemeral_public,
                "initiator_signature": session.initiator_signature,
                "initiator_rsa_public": session.initiator_rsa_public,
                "receiver_ephemeral_public": session.receiver_ephemeral_public,
                "receiver_signature": session.receiver_signature,
                "receiver_rsa_public": session.receiver_rsa_public
            }
            for session in incomplete_sessions
        ]
    }

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
                "updated_at": session.updated_at.isoformat(),
                "initiator_ephemeral_public": session.initiator_ephemeral_public,
                "initiator_signature": session.initiator_signature,
                "initiator_rsa_public": session.initiator_rsa_public,
                "receiver_ephemeral_public": session.receiver_ephemeral_public,
                "receiver_signature": session.receiver_signature,
                "receiver_rsa_public": session.receiver_rsa_public
            }
            for session in active_sessions
        ]
    }


@router.post("/close_session/{session_id}")
async def close_session(
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

    # Actualizar estado de la sesión a "closed"
    session.status = "closed"
    session.updated_at = datetime.utcnow()
    db.commit()

    # Notificar a ambos participantes a través de WebSocket
    asyncio.create_task(notify_session_update(session, "session_closed", db))

    return {
        "message": "Sesión cerrada correctamente"
    }

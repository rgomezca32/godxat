# backend/app/routes/user_status.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
import json

from app.database import SessionLocal, redis_client
from app.models import User, KeySession
from app.routes.auth import get_current_user
from app.routes.websocket import manager as websocket_manager

# Configuración para el estado activo
ACTIVE_EXPIRATION = 60  # segundos
TYPING_EXPIRATION = 5  # segundos

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/active_users/")
async def get_active_users(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene la lista de usuarios activos relacionados con el usuario actual"""
    # Buscar todas las sesiones activas donde el usuario es participante
    active_sessions = db.query(KeySession).filter(
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).all()

    # Obtener IDs de usuarios relacionados
    related_users = set()
    for session in active_sessions:
        if session.initiator_id == current_user.id:
            related_users.add(session.receiver_id)
        else:
            related_users.add(session.initiator_id)

    # Verificar estado activo de cada usuario
    active_users = []
    for user_id in related_users:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            continue

        # Verificar si está activo en Redis
        is_online = redis_client.exists(f"user:online:{user_id}")

        # Verificar si está escribiendo
        is_typing = False
        typing_session_id = None

        for session in active_sessions:
            if (session.initiator_id == user_id or session.receiver_id == user_id):
                typing_key = f"user:typing:{user_id}:{session.session_id}"
                if redis_client.exists(typing_key):
                    is_typing = True
                    typing_session_id = session.session_id
                    break

        active_users.append({
            "id": user.id,
            "username": user.username,
            "is_online": is_online,
            "is_typing": is_typing,
            "typing_session_id": typing_session_id
        })

    return {"active_users": active_users}


@router.post("/set_typing_status/{session_id}")
async def set_typing_status(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Establece el estado de escritura del usuario en una sesión específica"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    # Determinar el otro usuario en la sesión
    peer_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id

    # Guardar estado de escritura en Redis
    typing_key = f"user:typing:{current_user.id}:{session_id}"
    redis_client.setex(typing_key, TYPING_EXPIRATION, datetime.now(timezone.utc).isoformat())

    # Notificar al otro usuario a través de WebSocket
    await websocket_manager.send_personal_message({
        "event": "user_typing",
        "data": {
            "user_id": current_user.id,
            "session_id": session_id,
            "username": current_user.username
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, peer_id)

    return {"status": "ok"}


@router.get("/user_status/{user_id}")
async def get_user_status(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene el estado de un usuario específico"""
    # Verificar que el usuario existe
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Verificar que el usuario actual tiene una sesión activa con el usuario solicitado
    session = db.query(KeySession).filter(
        (
                ((KeySession.initiator_id == current_user.id) & (KeySession.receiver_id == user_id)) |
                ((KeySession.initiator_id == user_id) & (KeySession.receiver_id == current_user.id))
        ),
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver el estado de este usuario")

    # Verificar si está activo en Redis
    is_online = redis_client.exists(f"user:online:{user_id}")

    # Verificar si está escribiendo en esta sesión
    typing_key = f"user:typing:{user_id}:{session.session_id}"
    is_typing = redis_client.exists(typing_key)

    # Obtener última vez activo
    last_active = None
    last_active_key = f"user:last_active:{user_id}"
    last_active_str = redis_client.get(last_active_key)

    if last_active_str:
        try:
            last_active = datetime.fromisoformat(last_active_str.decode('utf-8'))
        except:
            pass

    return {
        "id": user.id,
        "username": user.username,
        "is_online": is_online,
        "is_typing": is_typing,
        "last_active": last_active.isoformat() if last_active else None
    }


@router.get("/session_status/{session_id}")
async def get_session_status(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene el estado de una sesión específica, incluyendo estado de los participantes"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id))
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    # Determinar el otro usuario en la sesión
    peer_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id
    peer = db.query(User).filter(User.id == peer_id).first()

    if not peer:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Verificar si el otro usuario está activo
    is_peer_online = redis_client.exists(f"user:online:{peer_id}")

    # Verificar si el otro usuario está escribiendo
    typing_key = f"user:typing:{peer_id}:{session_id}"
    is_peer_typing = redis_client.exists(typing_key)

    # Obtener última vez activo del otro usuario
    peer_last_active = None
    last_active_key = f"user:last_active:{peer_id}"
    last_active_str = redis_client.get(last_active_key)

    if last_active_str:
        try:
            peer_last_active = datetime.fromisoformat(last_active_str.decode('utf-8'))
        except:
            pass

    # Obtener último mensaje de la sesión
    last_message = db.query(KeySession).filter(
        KeySession.session_id == session_id
    ).order_by(KeySession.updated_at.desc()).first()

    return {
        "session_id": session.session_id,
        "status": session.status,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
        "peer": {
            "id": peer.id,
            "username": peer.username,
            "is_online": is_peer_online,
            "is_typing": is_peer_typing,
            "last_active": peer_last_active.isoformat() if peer_last_active else None
        },
        "last_message_at": last_message.created_at.isoformat() if last_message else None
    }


# Función para actualizar el estado activo de un usuario
async def update_user_active_status(user_id: int, is_online: bool = True):
    """Actualiza el estado activo de un usuario en Redis"""
    now = datetime.now(timezone.utc)

    if is_online:
        # Marcar como activo
        redis_client.setex(f"user:online:{user_id}", ACTIVE_EXPIRATION, now.isoformat())
    else:
        # Marcar como inactivo
        redis_client.delete(f"user:online:{user_id}")

    # Actualizar última vez activo
    redis_client.set(f"user:last_active:{user_id}", now.isoformat())

    return True


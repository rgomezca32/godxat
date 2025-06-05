import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal,redis_client,NONCE_EXPIRATION_SECONDS, MAX_ATTEMPTS_LOGIN
from app.models import User, Message, KeySession
from app.schemas import MessageCreate, EphemeralMessage
from app.routes.auth import get_current_user
from app.routes.websocket import notify_new_message
from datetime import datetime, timezone
import json

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/send_message_ephemeral/")
async def send_message_ephemeral(
        data: EphemeralMessage,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    session_id = data.session_id
    encrypted_message_json = data.message
    encrypted_message = json.loads(encrypted_message_json)

    now = datetime.now(timezone.utc)
    timestamp_str = encrypted_message['timestamp']
    timestamp = datetime.fromisoformat(timestamp_str)
    nonce = encrypted_message['nonce']

    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    if abs((now - timestamp).total_seconds()) > NONCE_EXPIRATION_SECONDS:
        raise HTTPException(status_code=400, detail="Mensaje vencido")

    if redis_client.get(f"nonce:{nonce}"):
        raise HTTPException(status_code=400, detail="Nonce ya usado (replay detectado)")

    redis_client.setex(f"nonce:{nonce}", NONCE_EXPIRATION_SECONDS, "1")

    receiver_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id

    last_message = db.query(Message).filter(
        Message.session_id == session_id
    ).order_by(Message.message_number.desc()).first()

    message_number = 1 if last_message is None else last_message.message_number + 1

    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_message=encrypted_message_json,
        session_id=session_id,
        message_number=message_number,
        created_at=datetime.utcnow()
    )
    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    # Ejecutar tarea asincrónica en segundo plano
    asyncio.create_task(notify_new_message(new_message, db))

    return {
        "message": "Mensaje enviado correctamente",
        "session_id": session_id,
        "message_number": message_number
    }



@router.get("/get_messages_ephemeral/{session_id}")
def get_messages_ephemeral(
        session_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene mensajes cifrados de una sesión"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id))
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    # Obtener todos los mensajes de la sesión
    messages = db.query(Message).filter(
        Message.session_id == session_id
    ).order_by(Message.created_at).all()

    # Preparar respuesta con mensajes cifrados
    encrypted_messages = []
    for msg in messages:
        sender = db.query(User).filter(User.id == msg.sender_id).first()

        encrypted_messages.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_username": sender.username if sender else "Unknown",
            "encrypted_message": msg.encrypted_message,  # Mensaje cifrado tal como está en la base de datos
            "created_at": msg.created_at.isoformat(),
            "message_number": msg.message_number
        })

    return {"messages": encrypted_messages}


@router.get("/get_all_messages_with_user/{user_id}")
def get_all_messages_with_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene todos los mensajes intercambiados con un usuario específico a través de todas las sesiones"""
    # Buscar todas las sesiones entre el usuario actual y el usuario especificado
    sessions = db.query(KeySession).filter(
        (
                ((KeySession.initiator_id == current_user.id) & (KeySession.receiver_id == user_id)) |
                ((KeySession.initiator_id == user_id) & (KeySession.receiver_id == current_user.id))
        )
    ).all()

    if not sessions:
        return {"messages": []}

    # Obtener mensajes de todas las sesiones
    all_encrypted_messages = []
    for session in sessions:
        # Obtener todos los mensajes de la sesión
        messages = db.query(Message).filter(
            Message.session_id == session.session_id
        ).order_by(Message.created_at).all()

        # Añadir mensajes cifrados a la lista
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()

            all_encrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": sender.username if sender else "Unknown",
                "encrypted_message": msg.encrypted_message,  # Mensaje cifrado tal como está en la base de datos
                "created_at": msg.created_at.isoformat(),
                "session_id": session.session_id,
                "message_number": msg.message_number
            })

    # Ordenar todos los mensajes por fecha
    all_encrypted_messages.sort(key=lambda x: x["created_at"])

    return {"messages": all_encrypted_messages}


@router.get("/get_conversations_ephemeral/")
def get_conversations_ephemeral(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Obtiene todas las conversaciones activas del usuario basadas en sesiones efímeras"""
    # Buscar todas las sesiones activas donde el usuario es participante
    active_sessions = db.query(KeySession).filter(
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).all()

    # Crear un diccionario para agrupar por usuario
    user_conversations = {}

    for session in active_sessions:
        # Determinar el otro usuario
        peer_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id

        # Si ya tenemos una conversación con este usuario, saltamos
        if peer_id in user_conversations:
            continue

        peer = db.query(User).filter(User.id == peer_id).first()
        if not peer:
            continue

        # Obtener el último mensaje de la sesión
        last_message = db.query(Message).filter(
            Message.session_id == session.session_id
        ).order_by(Message.created_at.desc()).first()


        user_conversations[peer_id] = {
            "peer_id": peer_id,
            "peer_username": peer.username,
            "session_id": session.session_id,
            "last_message_time": last_message.created_at.isoformat() if last_message else None,
            "has_unread": False
        }

    return {"conversations": list(user_conversations.values())}

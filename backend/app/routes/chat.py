from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User, Message, KeySession
from app.schemas import MessageCreate, EphemeralMessage
from app.routes.auth import get_current_user
from datetime import datetime
import json

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/send_message_ephemeral/")
def send_message_ephemeral(
        data: EphemeralMessage,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    session_id = data.session_id
    encrypted_message_json = data.message  # Este es el mensaje ya cifrado y firmado por el frontend

    """Envía un mensaje usando exclusivamente claves efímeras y firma RSA"""
    # Verificar que la sesión existe y está activa
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    # Determinar el receptor
    receiver_id = session.receiver_id if session.initiator_id == current_user.id else session.initiator_id

    # Obtener el último número de mensaje para esta sesión
    last_message = db.query(Message).filter(
        Message.session_id == session_id
    ).order_by(Message.message_number.desc()).first()

    message_number = 1 if last_message is None else last_message.message_number + 1

    # Nota: Ya no ciframos ni firmamos mensajes en el backend
    # El frontend envía el mensaje ya cifrado y firmado

    # Guardar el mensaje (JSON con cifrado y firma) en la base de datos
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_message=encrypted_message_json,  # Guardar el JSON completo recibido del frontend
        session_id=session_id,
        message_number=message_number,
        created_at=datetime.utcnow()
    )
    db.add(new_message)
    db.commit()

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

    # Nota: Ya no desciframos ni verificamos firmas en el backend
    # Solo devolvemos los mensajes cifrados para que el frontend los descifre

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

        # Nota: Ya no desciframos mensajes en el backend
        # Solo devolvemos información básica sobre la conversación

        user_conversations[peer_id] = {
            "peer_id": peer_id,
            "peer_username": peer.username,
            "session_id": session.session_id,
            "last_message_time": last_message.created_at.isoformat() if last_message else None,
            "has_unread": False  # Esta lógica podría implementarse si se desea
        }

    return {"conversations": list(user_conversations.values())}

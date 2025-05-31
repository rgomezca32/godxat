from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User, Message, KeySession
from app.schemas import MessageCreate, EphemeralMessage
from app.key_management import (
    encrypt_message_with_session, decrypt_message_with_session,
    load_ephemeral_keys, complete_session, load_private_key
)
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


def ensure_session_complete(username, session_id, db):
    """
    Asegura que la sesión esté completamente establecida para el iniciador
    """
    # Verificar si la sesión existe
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        KeySession.status == "active"
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión activa no encontrada")

    # Cargar las claves efímeras
    ephemeral_private, peer_ephemeral_public, role, peer_signature, peer_rsa_public = load_ephemeral_keys(username,
                                                                                                          session_id)

    # Si es el iniciador y no tiene la clave pública del receptor, completar la sesión
    if role == "initiator" and (not peer_ephemeral_public) and session.receiver_ephemeral_public:
        try:
            # Necesitamos la firma y la clave RSA pública del receptor para completar
            if not session.receiver_signature or not session.receiver_rsa_public:
                raise HTTPException(
                    status_code=500,
                    detail="Faltan datos del receptor (firma o clave RSA) para completar la sesión"
                )

            complete_session(
                username,
                session_id,
                session.receiver_ephemeral_public,
                session.receiver_signature,
                session.receiver_rsa_public
            )
            return True
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error al completar el establecimiento de sesión: {str(e)}"
            )

    return False


@router.post("/send_message_ephemeral/")
def send_message_ephemeral(
        data: EphemeralMessage,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    session_id = data.session_id
    message = data.message
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

    # Asegurar que la sesión esté completamente establecida para el iniciador
    ensure_session_complete(current_user.username, session_id, db)

    # Verificar que las claves efímeras están disponibles localmente
    ephemeral_private, peer_ephemeral_public, role, _, _ = load_ephemeral_keys(current_user.username, session_id)
    if not ephemeral_private or not peer_ephemeral_public:
        raise HTTPException(
            status_code=400,
            detail="No se encontraron las claves efímeras para esta sesión. Asegúrate de haber completado el establecimiento de sesión."
        )

    # Obtener el último número de mensaje para esta sesión
    last_message = db.query(Message).filter(
        Message.session_id == session_id
    ).order_by(Message.message_number.desc()).first()

    message_number = 1 if last_message is None else last_message.message_number + 1

    # Cargar la clave RSA privada del usuario para firmar el mensaje
    rsa_private, _ = load_private_key(current_user.username)
    if not rsa_private:
        raise HTTPException(status_code=500, detail="No se encontró la clave RSA privada del usuario")

    # Cifrar y firmar el mensaje usando claves efímeras y RSA
    try:
        encrypted_message_json = encrypt_message_with_session(
            message,
            current_user.username,
            session_id,
            message_number,
            rsa_private=rsa_private
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cifrar y firmar el mensaje: {str(e)}")

    # Guardar el mensaje (JSON con cifrado y firma) en la base de datos
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_message=encrypted_message_json,  # Guardar el JSON completo
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
    """Obtiene, verifica firma y descifra mensajes usando claves efímeras"""
    # Verificar que la sesión existe y el usuario es participante
    session = db.query(KeySession).filter(
        KeySession.session_id == session_id,
        ((KeySession.initiator_id == current_user.id) | (KeySession.receiver_id == current_user.id))
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    # Asegurar que la sesión esté completamente establecida para el iniciador
    ensure_session_complete(current_user.username, session_id, db)

    # Verificar que las claves efímeras están disponibles localmente
    ephemeral_private, peer_ephemeral_public, role, _, _ = load_ephemeral_keys(current_user.username, session_id)
    if not ephemeral_private or not peer_ephemeral_public:
        raise HTTPException(
            status_code=400,
            detail="No se encontraron las claves efímeras para esta sesión. No se pueden descifrar los mensajes."
        )

    # Obtener todos los mensajes de la sesión
    messages = db.query(Message).filter(
        Message.session_id == session_id
    ).order_by(Message.created_at).all()

    # Descifrar los mensajes
    decrypted_messages = []
    for msg in messages:
        try:
            # Obtener la clave RSA pública del remitente
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            if not sender or not sender.rsa_public_key:
                raise ValueError("No se encontró la clave RSA pública del remitente")

            sender_rsa_public = sender.rsa_public_key

            # Descifrar y verificar firma
            decrypted_text = decrypt_message_with_session(
                msg.encrypted_message,  # El JSON con cifrado y firma
                current_user.username,
                session_id,
                sender_rsa_public
            )
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": sender.username,
                "message": decrypted_text,
                "created_at": msg.created_at.isoformat(),
                "message_number": msg.message_number
            })
        except ValueError as e:
            # Si la firma es inválida o hay otro error de descifrado
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": db.query(User).filter(User.id == msg.sender_id).first().username,
                "message": f"[Error al procesar mensaje: {str(e)}]",
                "created_at": msg.created_at.isoformat(),
                "message_number": msg.message_number,
                "error": str(e)
            })
        except Exception as e:
            # Otros errores inesperados
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": db.query(User).filter(User.id == msg.sender_id).first().username,
                "message": "[Error inesperado al descifrar]",
                "created_at": msg.created_at.isoformat(),
                "message_number": msg.message_number,
                "error": str(e)
            })

    return {"messages": decrypted_messages}


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
    all_messages = []
    for session in sessions:
        try:
            # Asegurar que la sesión esté completamente establecida para el iniciador
            if session.status == "active":
                ensure_session_complete(current_user.username, session.session_id, db)

            # Verificar que las claves efímeras están disponibles localmente
            ephemeral_private, peer_ephemeral_public, role, _, _ = load_ephemeral_keys(
                current_user.username, session.session_id
            )

            if not ephemeral_private or not peer_ephemeral_public:
                continue  # Saltar esta sesión si no se pueden cargar las claves

            # Obtener todos los mensajes de la sesión
            messages = db.query(Message).filter(
                Message.session_id == session.session_id
            ).order_by(Message.created_at).all()

            # Descifrar los mensajes
            for msg in messages:
                try:
                    # Obtener la clave RSA pública del remitente
                    sender = db.query(User).filter(User.id == msg.sender_id).first()
                    if not sender or not sender.rsa_public_key:
                        raise ValueError("No se encontró la clave RSA pública del remitente")

                    sender_rsa_public = sender.rsa_public_key

                    # Descifrar y verificar firma
                    decrypted_text = decrypt_message_with_session(
                        msg.encrypted_message,  # El JSON con cifrado y firma
                        current_user.username,
                        session.session_id,
                        sender_rsa_public
                    )
                    all_messages.append({
                        "id": msg.id,
                        "sender_id": msg.sender_id,
                        "sender_username": sender.username,
                        "message": decrypted_text,
                        "created_at": msg.created_at.isoformat(),
                        "session_id": session.session_id,
                        "message_number": msg.message_number
                    })
                except ValueError as e:
                    # Si la firma es inválida o hay otro error de descifrado
                    all_messages.append({
                        "id": msg.id,
                        "sender_id": msg.sender_id,
                        "sender_username": db.query(User).filter(User.id == msg.sender_id).first().username,
                        "message": f"[Error al procesar mensaje: {str(e)}]",
                        "created_at": msg.created_at.isoformat(),
                        "session_id": session.session_id,
                        "message_number": msg.message_number,
                        "error": str(e)
                    })
                except Exception as e:
                    # Otros errores inesperados
                    all_messages.append({
                        "id": msg.id,
                        "sender_id": msg.sender_id,
                        "sender_username": db.query(User).filter(User.id == msg.sender_id).first().username,
                        "message": "[Error inesperado al descifrar]",
                        "created_at": msg.created_at.isoformat(),
                        "session_id": session.session_id,
                        "message_number": msg.message_number,
                        "error": str(e)
                    })
        except Exception as e:
            # Si hay error con la sesión, continuar con la siguiente
            continue

    # Ordenar todos los mensajes por fecha
    all_messages.sort(key=lambda x: x["created_at"])

    return {"messages": all_messages}


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

        # Asegurar que la sesión esté completamente establecida para el iniciador
        if session.initiator_id == current_user.id:
            try:
                ensure_session_complete(current_user.username, session.session_id, db)
            except:
                # Si hay error al completar la sesión, intentamos mostrar la conversación de todos modos
                pass

        # Obtener el último mensaje de la sesión
        last_message = db.query(Message).filter(
            Message.session_id == session.session_id
        ).order_by(Message.created_at.desc()).first()

        last_message_preview = None
        last_message_time = None

        if last_message:
            try:
                # Obtener la clave RSA pública del remitente del último mensaje
                sender = db.query(User).filter(User.id == last_message.sender_id).first()
                if not sender or not sender.rsa_public_key:
                    raise ValueError("No se encontró la clave RSA pública del remitente")

                sender_rsa_public = sender.rsa_public_key

                # Descifrar y verificar firma
                decrypted_text = decrypt_message_with_session(
                    last_message.encrypted_message,
                    current_user.username,
                    session.session_id,
                    sender_rsa_public
                )
                last_message_preview = decrypted_text[:50] + "..." if len(decrypted_text) > 50 else decrypted_text
                last_message_time = last_message.created_at.isoformat()
            except:
                last_message_preview = "[Error al procesar último mensaje]"

        user_conversations[peer_id] = {
            "session_id": session.session_id,
            "peer_id": peer_id,
            "peer_username": peer.username,
            "last_message": last_message_preview,
            "last_message_time": last_message_time,
            "role": "initiator" if session.initiator_id == current_user.id else "receiver"
        }

    return {"conversations": list(user_conversations.values())}


@router.delete("/delete_message_ephemeral/{message_id}")
def delete_message_ephemeral(
        message_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Elimina un mensaje enviado con claves efímeras"""
    # Buscar el mensaje
    message = db.query(Message).filter(Message.id == message_id).first()

    if not message:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado")

    # Verificar que el usuario es el remitente
    if message.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para eliminar este mensaje")

    # Eliminar el mensaje
    db.delete(message)
    db.commit()

    return {"message": "Mensaje eliminado correctamente"}


# Endpoints de compatibilidad (pueden necesitar ajustes si se usan)

@router.post("/send_message_auth/")
def send_message_auth(
        msg: MessageCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Versión compatible con la API anterior que ahora usa claves efímeras
    """
    # Buscar una sesión activa con el receptor o crear una nueva
    session = db.query(KeySession).filter(
        ((KeySession.initiator_id == current_user.id) & (KeySession.receiver_id == msg.receiver_id)) |
        ((KeySession.initiator_id == msg.receiver_id) & (KeySession.receiver_id == current_user.id)),
        KeySession.status == "active"
    ).first()

    if not session:
        # No hay sesión activa, verificar si ya existe una sesión pendiente
        pending_session = db.query(KeySession).filter(
            ((KeySession.initiator_id == current_user.id) & (KeySession.receiver_id == msg.receiver_id)) |
            ((KeySession.initiator_id == msg.receiver_id) & (KeySession.receiver_id == current_user.id)),
            KeySession.status == "pending"
        ).first()

        if pending_session:
            return {
                "message": "Ya existe una solicitud de sesión pendiente con este usuario",
                "session_id": pending_session.session_id,
                "status": "pending"
            }

        # Iniciar el proceso de establecimiento
        from routes.auth import initiate_session_endpoint

        # Iniciar sesión
        initiate_result = initiate_session_endpoint(msg.receiver_id, db, current_user)
        session_id = initiate_result["session_id"]

        # Informar al usuario que debe completar el establecimiento de sesión
        return {
            "message": "Se ha iniciado una nueva sesión. El receptor debe aceptarla antes de poder enviar mensajes.",
            "session_id": session_id,
            "status": "pending"
        }

    # Asegurar que la sesión esté completamente establecida para el iniciador
    if session.initiator_id == current_user.id:
        ensure_session_complete(current_user.username, session.session_id, db)

    # Usar la sesión existente para enviar el mensaje
    ephemeral_msg = EphemeralMessage(session_id=session.session_id, message=msg.message)
    return send_message_ephemeral(ephemeral_msg, db, current_user)


@router.get("/get_messages_auth/{friend_id}")
def get_messages_auth(
        friend_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Versión compatible con la API anterior que ahora usa claves efímeras
    """
    # Usar el nuevo endpoint para obtener todos los mensajes con el usuario
    all_messages = get_all_messages_with_user(friend_id, db, current_user)

    # Convertir al formato anterior para compatibilidad
    compatible_messages = [
        {"sender": msg["sender_id"], "message": msg["message"]}
        for msg in all_messages["messages"]
        if not msg.get("error")  # Solo incluir mensajes válidos
    ]

    return {"messages": compatible_messages}


@router.get("/get_conversations_auth/")
def get_conversations_auth(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Versión compatible con la API anterior que ahora usa claves efímeras
    """
    # Usar la nueva implementación
    conversations = get_conversations_ephemeral(db, current_user)

    # Convertir al formato anterior para compatibilidad
    compatible_conversations = {
        "conversations": [
            {"friend_id": conv["peer_id"]}
            for conv in conversations["conversations"]
        ]
    }

    return compatible_conversations

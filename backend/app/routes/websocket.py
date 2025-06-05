# backend/app/routes/websocket.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from typing import Dict, List, Optional, Set
import json
import asyncio
import logging
from datetime import datetime, timezone

from app.database import SessionLocal, redis_client
from app.models import User, Message, KeySession
from app.security import SECRET_KEY, ALGORITHM

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Router para WebSockets
router = APIRouter()


# Clase para gestionar conexiones WebSocket
class ConnectionManager:
    def __init__(self):
        # Diccionario para almacenar conexiones activas: {user_id: [conexiones]}
        self.active_connections: Dict[int, List[WebSocket]] = {}
        # Conjunto para almacenar usuarios activos
        self.active_users: Set[int] = set()
        # Tiempo de expiración para estado activo (segundos)
        self.active_expiration = 60

    async def connect(self, websocket: WebSocket, user_id: int):
        """Conecta un nuevo cliente WebSocket"""

        # Inicializar lista de conexiones para el usuario si no existe
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []

        # Añadir la conexión a la lista del usuario
        self.active_connections[user_id].append(websocket)

        # Marcar usuario como activo
        self.active_users.add(user_id)

        # Actualizar estado activo en Redis
        redis_client.setex(f"user:online:{user_id}", self.active_expiration, datetime.now(timezone.utc).isoformat())

        # Notificar a otros usuarios que este usuario está en línea
        await self.broadcast_user_status(user_id, "user_online")

        logger.info(f"Usuario {user_id} conectado. Total conexiones: {len(self.active_connections[user_id])}")

    async def disconnect(self, websocket: WebSocket, user_id: int):
        """Desconecta un cliente WebSocket"""
        # Eliminar la conexión de la lista del usuario
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)

            # Si no quedan conexiones para el usuario, eliminarlo del diccionario
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                self.active_users.remove(user_id)

                # Eliminar estado activo en Redis
                redis_client.delete(f"user:online:{user_id}")

                # Notificar a otros usuarios que este usuario está desconectado
                await self.broadcast_user_status(user_id, "user_offline")

        logger.info(
            f"Usuario {user_id} desconectado. Conexiones restantes: {len(self.active_connections.get(user_id, []))}")

    async def send_personal_message(self, message: dict, user_id: int):
        """Envía un mensaje a todas las conexiones de un usuario específico"""
        if user_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error al enviar mensaje a usuario {user_id}: {str(e)}")
                    disconnected.append(connection)

            # Limpiar conexiones desconectadas
            for conn in disconnected:
                if conn in self.active_connections[user_id]:
                    self.active_connections[user_id].remove(conn)

            # Si no quedan conexiones, eliminar usuario
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                self.active_users.remove(user_id)
                redis_client.delete(f"user:online:{user_id}")

    async def broadcast(self, message: dict):
        """Envía un mensaje a todos los usuarios conectados"""
        disconnected_users = []
        for user_id, connections in self.active_connections.items():
            disconnected = []
            for connection in connections:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error al enviar broadcast a usuario {user_id}: {str(e)}")
                    disconnected.append(connection)

            # Limpiar conexiones desconectadas
            for conn in disconnected:
                if conn in self.active_connections[user_id]:
                    self.active_connections[user_id].remove(conn)

            # Si no quedan conexiones, marcar usuario para eliminar
            if not self.active_connections[user_id]:
                disconnected_users.append(user_id)

        # Eliminar usuarios desconectados
        for user_id in disconnected_users:
            if user_id in self.active_connections:
                del self.active_connections[user_id]
                self.active_users.remove(user_id)
                redis_client.delete(f"user:online:{user_id}")

    async def broadcast_to_users(self, message: dict, user_ids: List[int]):
        """Envía un mensaje a un conjunto específico de usuarios"""
        for user_id in user_ids:
            if user_id in self.active_connections:
                await self.send_personal_message(message, user_id)

    async def broadcast_user_status(self, user_id: int, status: str):
        """Notifica el cambio de estado de un usuario a usuarios relevantes"""
        # Obtener usuarios que tienen sesiones activas con este usuario
        db = SessionLocal()
        try:
            # Buscar sesiones activas donde el usuario es participante
            sessions = db.query(KeySession).filter(
                ((KeySession.initiator_id == user_id) | (KeySession.receiver_id == user_id)),
                KeySession.status == "active"
            ).all()

            # Obtener IDs de usuarios relacionados
            related_users = set()
            for session in sessions:
                if session.initiator_id == user_id:
                    related_users.add(session.receiver_id)
                else:
                    related_users.add(session.initiator_id)

            # Obtener información del usuario
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return

            # Crear mensaje de estado
            status_message = {
                "event": status,
                "data": {
                    "user_id": user_id,
                    "username": user.username
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Enviar a usuarios relacionados
            await self.broadcast_to_users(status_message, list(related_users))

        finally:
            db.close()

    def is_user_online(self, user_id: int) -> bool:
        """Verifica si un usuario está en línea"""
        # Verificar en memoria
        if user_id in self.active_users:
            return True

        # Verificar en Redis
        return redis_client.exists(f"user:online:{user_id}") == 1

    async def update_user_activity(self, user_id: int):
        """Actualiza el timestamp de actividad del usuario"""
        if user_id in self.active_users:
            # Actualizar timestamp en Redis
            redis_client.setex(f"user:online:{user_id}", self.active_expiration, datetime.now(timezone.utc).isoformat())

    async def get_online_users_for_user(self, user_id: int) -> List[Dict]:
        """Obtiene la lista de usuarios en línea relacionados con un usuario específico"""
        db = SessionLocal()
        try:
            # Buscar sesiones activas donde el usuario es participante
            sessions = db.query(KeySession).filter(
                ((KeySession.initiator_id == user_id) | (KeySession.receiver_id == user_id)),
                KeySession.status == "active"
            ).all()

            # Obtener IDs de usuarios relacionados
            related_users = set()
            for session in sessions:
                if session.initiator_id == user_id:
                    related_users.add(session.receiver_id)
                else:
                    related_users.add(session.initiator_id)

            # Verificar estado en línea y preparar respuesta
            online_users = []
            for related_id in related_users:
                if self.is_user_online(related_id):
                    user = db.query(User).filter(User.id == related_id).first()
                    if user:
                        online_users.append({
                            "user_id": user.id,
                            "username": user.username
                        })

            return online_users
        finally:
            db.close()


# Instancia global del gestor de conexiones
manager = ConnectionManager()


# Función para obtener usuario desde token JWT en WebSocket
async def get_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None

        user = db.query(User).filter(User.username == username).first()
        return user
    except JWTError:
        return None
    except Exception as e:
        logger.error(f"Error al verificar token: {str(e)}")
        return None


# Endpoint WebSocket principal
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    user_id = None

    try:
        # Esperar mensaje de autenticación
        auth_text = await websocket.receive_text()
        auth_data = json.loads(auth_text)

        if auth_data.get("event") != "auth" or "token" not in auth_data.get("data", {}):
            await websocket.send_text(json.dumps({
                "event": "error",
                "data": {"message": "Autenticación requerida"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
            await websocket.close()
            return

        # Verificar token
        token = auth_data["data"]["token"]
        db = SessionLocal()
        try:
            user = await get_user_from_token(token, db)
            if not user:
                await websocket.send_text(json.dumps({
                    "event": "error",
                    "data": {"message": "Token inválido"},
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))
                await websocket.close()
                return

            user_id = user.id

            # Registrar conexión
            await manager.connect(websocket, user_id)

            # Enviar confirmación de autenticación
            await websocket.send_text(json.dumps({
                "event": "auth_success",
                "data": {
                    "user_id": user.id,
                    "username": user.username
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))

            # Enviar estado inicial
            await send_initial_state(websocket, user, db)

            # Bucle principal para recibir mensajes
            while True:
                data = await websocket.receive_text()
                message_data = json.loads(data)

                # Procesar mensaje según su tipo
                event_type = message_data.get("event")

                if event_type == "ping":
                    # Responder con pong y actualizar actividad
                    await websocket.send_text(json.dumps({
                        "event": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))
                    await manager.update_user_activity(user_id)

                elif event_type == "message_delivered":
                    # Procesar confirmación de entrega de mensaje
                    message_id = message_data.get("data", {}).get("message_id")
                    if message_id:
                        # Aquí se podría actualizar el estado del mensaje en la base de datos
                        # y notificar al remitente original
                        message = db.query(Message).filter(Message.id == message_id).first()
                        if message:
                            # Notificar al remitente
                            await manager.send_personal_message({
                                "event": "message_delivered",
                                "data": {
                                    "message_id": message_id,
                                    "session_id": message.session_id
                                },
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }, message.sender_id)

                elif event_type == "message_read":
                    # Procesar confirmación de lectura de mensaje
                    message_id = message_data.get("data", {}).get("message_id")
                    if message_id:
                        # Aquí se podría actualizar el estado del mensaje en la base de datos
                        # y notificar al remitente original
                        message = db.query(Message).filter(Message.id == message_id).first()
                        if message:
                            # Notificar al remitente
                            await manager.send_personal_message({
                                "event": "message_read",
                                "data": {
                                    "message_id": message_id,
                                    "session_id": message.session_id
                                },
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }, message.sender_id)

                elif event_type == "user_typing":
                    # Procesar notificación de usuario escribiendo
                    session_id = message_data.get("data", {}).get("session_id")
                    if session_id:
                        session = db.query(KeySession).filter(KeySession.session_id == session_id).first()
                        if session:
                            # Determinar el destinatario
                            recipient_id = session.receiver_id if session.initiator_id == user_id else session.initiator_id
                            # Notificar al destinatario
                            await manager.send_personal_message({
                                "event": "user_typing",
                                "data": {
                                    "user_id": user_id,
                                    "session_id": session_id
                                },
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }, recipient_id)

                elif event_type == "get_online_users":
                    # Nuevo evento para solicitar usuarios en línea
                    online_users = await manager.get_online_users_for_user(user_id)
                    await websocket.send_text(json.dumps({
                        "event": "online_users_update",
                        "data": {"users": online_users},
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))

        finally:
            db.close()

    except WebSocketDisconnect:
        if user_id:
            db = SessionLocal()
            try:
                await manager.disconnect(websocket, user_id)
            finally:
                db.close()
    except Exception as e:
        logger.error(f"Error en WebSocket: {str(e)}")
        if user_id:
            db = SessionLocal()
            try:
                await manager.disconnect(websocket, user_id)
            finally:
                db.close()


async def send_initial_state(websocket: WebSocket, user: User, db: Session):
    """Envía el estado inicial al cliente recién conectado"""
    try:
        # 1. Enviar sesiones pendientes
        pending_sessions = db.query(KeySession).filter(
            KeySession.receiver_id == user.id,
            KeySession.status == "pending"
        ).all()

        if pending_sessions:
            pending_data = []
            for session in pending_sessions:
                initiator = db.query(User).filter(User.id == session.initiator_id).first()
                if initiator:
                    pending_data.append({
                        "session_id": session.session_id,
                        "initiator_id": session.initiator_id,
                        "initiator_username": initiator.username,
                        "created_at": session.created_at.isoformat()
                    })

            if pending_data:
                await websocket.send_text(json.dumps({
                    "event": "pending_sessions",
                    "data": {"sessions": pending_data},
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))

        # 2. Enviar sesiones incompletas
        incomplete_sessions = db.query(KeySession).filter(
            KeySession.initiator_id == user.id,
            KeySession.status == "incomplete"
        ).all()

        if incomplete_sessions:
            incomplete_data = []
            for session in incomplete_sessions:
                receiver = db.query(User).filter(User.id == session.receiver_id).first()
                if receiver:
                    incomplete_data.append({
                        "session_id": session.session_id,
                        "receiver_id": session.receiver_id,
                        "receiver_username": receiver.username,
                        "created_at": session.created_at.isoformat()
                    })

            if incomplete_data:
                await websocket.send_text(json.dumps({
                    "event": "incomplete_sessions",
                    "data": {"sessions": incomplete_data},
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))

        # 3. Enviar estado de usuarios en conversaciones activas
        # Mejorado: Obtener todos los usuarios en línea relacionados con este usuario
        online_users = await manager.get_online_users_for_user(user.id)

        if online_users:
            await websocket.send_text(json.dumps({
                "event": "online_users",
                "data": {"users": online_users},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))

    except Exception as e:
        logger.error(f"Error al enviar estado inicial: {str(e)}")


# Función para notificar nuevo mensaje
async def notify_new_message(message: Message, db: Session):
    """Notifica a los usuarios relevantes sobre un nuevo mensaje"""
    try:
        # Obtener información del mensaje
        message_data = {
            "event": "new_message",
            "data": {
                "message_id": message.id,
                "session_id": message.session_id,
                "sender_id": message.sender_id,
                "receiver_id": message.receiver_id,
                "message_number": message.message_number,
                "created_at": message.created_at.isoformat()
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Notificar al receptor
        await manager.send_personal_message(message_data, message.receiver_id)

    except Exception as e:
        logger.error(f"Error al notificar nuevo mensaje: {str(e)}")


# Función para notificar cambio de estado de sesión
async def notify_session_update(session: KeySession, event_type: str, db: Session):
    """Notifica a los usuarios relevantes sobre un cambio en el estado de una sesión"""
    try:
        # Determinar destinatarios según el tipo de evento
        if event_type == "session_request":
            # Notificar al receptor sobre nueva solicitud
            session_data = {
                "event": "session_request",
                "data": {
                    "session_id": session.session_id,
                    "initiator_id": session.initiator_id,
                    "initiator_username": db.query(User).filter(User.id == session.initiator_id).first().username,
                    "created_at": session.created_at.isoformat()
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(session_data, session.receiver_id)

        elif event_type == "session_accepted":
            # Notificar al iniciador que su solicitud fue aceptada
            session_data = {
                "event": "session_accepted",
                "data": {
                    "session_id": session.session_id,
                    "receiver_id": session.receiver_id,
                    "receiver_username": db.query(User).filter(User.id == session.receiver_id).first().username,
                    "updated_at": session.updated_at.isoformat()
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(session_data, session.initiator_id)

        elif event_type == "session_rejected":
            # Notificar al iniciador que su solicitud fue rechazada
            session_data = {
                "event": "session_rejected",
                "data": {
                    "session_id": session.session_id,
                    "receiver_id": session.receiver_id,
                    "receiver_username": db.query(User).filter(User.id == session.receiver_id).first().username
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(session_data, session.initiator_id)

        elif event_type == "session_completed":
            # Notificar al receptor que la sesión está completa
            session_data = {
                "event": "session_completed",
                "data": {
                    "session_id": session.session_id,
                    "initiator_id": session.initiator_id,
                    "initiator_username": db.query(User).filter(User.id == session.initiator_id).first().username,
                    "updated_at": session.updated_at.isoformat()
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(session_data, session.receiver_id)

            # También notificar al iniciador para confirmar que la sesión está completa
            initiator_data = {
                "event": "session_completion_confirmed",
                "data": {
                    "session_id": session.session_id,
                    "receiver_id": session.receiver_id,
                    "receiver_username": db.query(User).filter(User.id == session.receiver_id).first().username,
                    "updated_at": session.updated_at.isoformat()
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(initiator_data, session.initiator_id)

        elif event_type == "session_closed":
            # Notificar a ambos usuarios que la sesión fue cerrada
            session_data = {
                "event": "session_closed",
                "data": {
                    "session_id": session.session_id,
                    "updated_at": session.updated_at.isoformat()
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await manager.send_personal_message(session_data, session.initiator_id)
            await manager.send_personal_message(session_data, session.receiver_id)

    except Exception as e:
        logger.error(f"Error al notificar actualización de sesión: {str(e)}")


# Tarea en segundo plano para verificar usuarios inactivos
async def check_inactive_users():
    """Verifica periódicamente usuarios inactivos y actualiza su estado"""
    while True:
        try:
            # Esperar intervalo (cada 30 segundos)
            await asyncio.sleep(30)

            # Obtener todos los usuarios marcados como activos
            active_keys = redis_client.keys("user:online:*")

            for key in active_keys:
                # Extraer user_id de la clave
                user_id = int(key.decode('utf-8').split(":")[-1])

                # Verificar si el usuario tiene conexiones activas
                if user_id not in manager.active_users:
                    # Si no tiene conexiones pero está marcado como activo en Redis,
                    # significa que perdió conexión sin cerrarla correctamente
                    redis_client.delete(key)

                    # Notificar a usuarios relevantes
                    db = SessionLocal()
                    try:
                        await manager.broadcast_user_status(user_id, "user_offline")
                    finally:
                        db.close()

        except Exception as e:
            logger.error(f"Error en tarea de verificación de usuarios inactivos: {str(e)}")


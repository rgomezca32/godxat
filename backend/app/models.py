from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base  # ✅ Esto es lo correcto

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    rsa_public_key = Column(Text)  # Cambiado a Text para almacenar claves más largas
    dh_public_key = Column(Text)   # Cambiado a Text para almacenar claves más largas
    created_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    encrypted_message = Column(Text)  # Cambiado a Text para almacenar mensajes cifrados y firmados en JSON
    session_id = Column(String, index=True)  # Referencia a la sesión de claves usada
    message_number = Column(Integer)  # Número secuencial del mensaje en la sesión
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relaciones
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])


class KeySession(Base):
    __tablename__ = "key_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)  # Identificador único de la sesión
    initiator_id = Column(Integer, ForeignKey("users.id"))  # Usuario que inicia la sesión
    receiver_id = Column(Integer, ForeignKey("users.id"))  # Usuario que recibe la invitación
    initiator_ephemeral_public = Column(Text)  # Clave DH pública efímera del iniciador
    receiver_ephemeral_public = Column(Text)  # Clave DH pública efímera del receptor
    initiator_signature = Column(Text)  # Firma RSA de la clave DH pública del iniciador
    receiver_signature = Column(Text)  # Firma RSA de la clave DH pública del receptor
    initiator_rsa_public = Column(Text)  # Clave RSA pública del iniciador
    receiver_rsa_public = Column(Text)  # Clave RSA pública del receptor
    status = Column(String)  # "pending", "active", "closed"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relaciones
    initiator = relationship("User", foreign_keys=[initiator_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

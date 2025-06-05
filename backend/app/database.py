# backend/app/database.py
import os

import redis
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Obtener URL de la base de datos desde variables de entorno y variables de entorno
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
NONCE_EXPIRATION_SECONDS = int(os.getenv("NONCE_EXPIRATION_SECONDS"))
BLOCK_TIME_SECONDS = int(os.getenv("BLOCK_TIME_SECONDS"))
MAX_ATTEMPTS_LOGIN = int(os.getenv("MAX_ATTEMPTS_LOGIN"))

# Si estamos en Render.com, la URL de PostgreSQL comienza con "postgres://"
# pero SQLAlchemy requiere "postgresql://"
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Verificar si es SQLite para pasar connect_args
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

# Crear sesión
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Crear base para modelos declarativos
Base = declarative_base()

# Función para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Inicializar cliente Redis
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
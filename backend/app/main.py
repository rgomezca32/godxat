# backend/app/main.py
import asyncio
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from contextlib import asynccontextmanager

# Importar rutas
from app.routes import auth, chat, websocket, user_status
from app.routes.websocket import check_inactive_users

# Cargar variables de entorno
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(check_inactive_users())
    yield

app = FastAPI(title="GodXat API", version="1.0.0", lifespan=lifespan)

# Configurar CORS
origins = os.getenv("CORS_ORIGINS", "").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(websocket.router)
app.include_router(user_status.router)

# Ruta de salud para monitoreo
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/list_keys")
def list_keys():
    keys_dir = os.path.expanduser("~/.secure_chat_keys")
    if not os.path.exists(keys_dir):
        return {"error": "Keys directory not found"}
    files = os.listdir(keys_dir)
    return {"files": files}

# Si este archivo se ejecuta directamente
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
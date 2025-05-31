# backend/app/main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Importar rutas
from app.routes import auth, chat

# Cargar variables de entorno
load_dotenv()

# Crear aplicación FastAPI
app = FastAPI(title="GodXat API", version="1.0.0")

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

# Ruta de salud para monitoreo
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Si este archivo se ejecuta directamente
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
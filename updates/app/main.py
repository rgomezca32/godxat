# updates/app/main.py
from fastapi import FastAPI, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Dict, Optional
import json
import os
from pathlib import Path
import logging
from datetime import datetime

# --- Configuración de Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuración ---
# Directorio donde se almacenan los archivos JSON de las versiones
VERSIONS_DIR = Path(os.getenv("VERSIONS_DATA_DIR", "/tmp/versions"))
# Clave API para proteger el endpoint de publicación (¡CAMBIAR EN PRODUCCIÓN!)
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "tu_clave_api_secreta_para_updates")

# Asegura que el directorio de versiones exista
VERSIONS_DIR.mkdir(parents=True, exist_ok=True)


# --- Modelos Pydantic ---
class PlatformInfo(BaseModel):
    signature: str = Field(..., description="Firma digital del archivo de actualización")
    url: str = Field(..., description="URL de descarga del archivo de actualización")


class UpdateInfo(BaseModel):
    version: str = Field(..., description="Número de versión (e.g., 1.0.1)")
    notes: str = Field(..., description="Notas de la versión o changelog")
    pub_date: datetime = Field(..., description="Fecha de publicación en formato ISO 8601")
    platforms: Dict[str, PlatformInfo] = Field(...,
                                               description="Diccionario con información por plataforma (e.g., windows-x86_64)")


# --- Seguridad API Admin ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == ADMIN_API_KEY:
        return api_key
    else:
        logger.warning(f"Intento de acceso no autorizado a endpoint admin.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clave API inválida o faltante",
        )


# --- Aplicación FastAPI ---
app = FastAPI(title="GodXat Update Server")


# --- Endpoints ---
@app.get("/api/{target}/{current_version}",
         response_model=UpdateInfo,
         summary="Comprobar actualizaciones",
         description="Endpoint consultado por la aplicación Tauri para buscar actualizaciones.")
async def check_update(target: str, current_version: str):
    """Comprueba si hay una versión más reciente disponible para una plataforma específica."""
    latest_file = VERSIONS_DIR / "latest.json"
    logger.info(f"Comprobando actualizaciones para target={target}, current_version={current_version}")

    if not latest_file.exists():
        logger.warning(f"No se encontró el archivo latest.json en {VERSIONS_DIR}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No hay información de actualizaciones disponible.")

    try:
        with open(latest_file, "r") as f:
            latest_info_data = json.load(f)
        latest_info = UpdateInfo(**latest_info_data)  # Validar con Pydantic
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Error al leer o parsear latest.json: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error interno al procesar la información de actualización.")

    # Comparar versiones (asumiendo formato semántico simple X.Y.Z)
    # Una comparación más robusta podría usar librerías como packaging.version
    try:
        from packaging.version import parse as parse_version
        is_newer = parse_version(latest_info.version) > parse_version(current_version)
    except ImportError:
        # Fallback a comparación simple si packaging no está disponible
        is_newer = latest_info.version != current_version  # Simplista, asume que latest siempre es > o =
    except Exception as e:
        logger.error(f"Error comparando versiones {latest_info.version} y {current_version}: {e}")
        is_newer = False  # Asumir que no es más nueva si hay error

    if not is_newer:
        logger.info(f"La versión {current_version} ya es la última o más reciente.")
        # Devolver 204 No Content si no hay actualización
        # Sin embargo, Tauri espera un 200 OK con datos o un 204 vacío.
        # Devolver 404 podría ser interpretado como error por algunos clientes.
        # Devolveremos 204 como indica la especificación de Tauri.
        # ¡OJO! FastAPI no permite devolver 204 con cuerpo, así que devolvemos una excepción que lo fuerce.
        raise HTTPException(status_code=status.HTTP_204_NO_CONTENT)

    # Verificar si la plataforma solicitada está en la actualización
    if target not in latest_info.platforms:
        logger.warning(f"Plataforma {target} no encontrada en la versión {latest_info.version}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Actualización no disponible para la plataforma {target}")

    logger.info(f"Actualización encontrada: v{latest_info.version} para {target}")
    return latest_info


@app.post("/admin/publish",
          status_code=status.HTTP_201_CREATED,
          summary="Publicar nueva actualización (protegido)",
          description="Endpoint para publicar la información de una nueva versión. Requiere API Key.")
async def publish_update(update_info: UpdateInfo, api_key: str = Security(get_api_key)):
    """Guarda la información de una nueva actualización y la marca como la última."""
    version_file = VERSIONS_DIR / f"{update_info.version}.json"
    latest_file = VERSIONS_DIR / "latest.json"

    logger.info(f"Recibida solicitud para publicar versión {update_info.version}")

    try:
        # Guardar la información específica de la versión
        with open(version_file, "w") as f:
            # Usamos .dict() para convertir el modelo Pydantic a diccionario
            # Usamos default=str para manejar datetime
            json.dump(update_info.dict(), f, indent=2, default=str)
        logger.info(f"Archivo de versión guardado: {version_file}")

        # Actualizar el archivo latest.json
        with open(latest_file, "w") as f:
            json.dump(update_info.dict(), f, indent=2, default=str)
        logger.info(f"Archivo latest.json actualizado a versión {update_info.version}")

        return {"status": "success", "message": f"Actualización {update_info.version} publicada correctamente."}
    except IOError as e:
        logger.error(f"Error de I/O al guardar archivos de actualización: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error al guardar la información de la actualización.")
    except Exception as e:
        logger.error(f"Error inesperado al publicar actualización: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error inesperado.")


@app.get("/health", tags=["System"], summary="Verificación de salud")
async def health_check():
    """Endpoint simple para verificar que el servicio está funcionando."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
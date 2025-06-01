from app.database import Base, engine
from app import models  # Para que se registren tus modelos en Base

Base.metadata.create_all(bind=engine)
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.auth import router as auth_router
from app.database import db
from app.models import User

app = FastAPI()

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Configurar Jinja2 templates
templates = Jinja2Templates(directory="app/templates")

# Incluir rutas del enrutador de autenticación sin duplicar el prefijo
app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.on_event("startup")
async def startup():
    if db.is_closed():
        db.connect()
    db.create_tables([User])

@app.on_event("shutdown")
async def shutdown():
    if not db.is_closed():
        db.close()

# Ejecutar el servidor en un puerto específico
# uvicorn app.main:app --reload --port 8000

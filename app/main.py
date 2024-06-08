from fastapi import FastAPI
from .database import database
from .auth import router as auth_router
from .models import User

app = FastAPI()

@app.on_event("startup")
async def startup():
    if database.is_closed():
        database.connect()
    database.create_tables([User])

@app.on_event("shutdown")
async def shutdown():
    if not database.is_closed():
        database.close()

app.include_router(auth_router, prefix="/auth", tags=["auth"])

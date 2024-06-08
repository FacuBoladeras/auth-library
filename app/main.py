from fastapi import FastAPI
from .database import db
from .auth import router as auth_router
from .models import User

app = FastAPI()

# uvicorn app.main:app --reload

@app.on_event("startup")
async def startup():
    if db.is_closed():
        db.connect()
    db.create_tables([User])

@app.on_event("shutdown")
async def shutdown():
    if not db.is_closed():
        db.close()

app.include_router(auth_router, prefix="/auth", tags=["auth"])

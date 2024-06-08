from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from .schemas import UserCreate, UserLogin, Token
from .models import User
from .utils import get_password_hash, verify_password, create_access_token
from datetime import timedelta
from .config import settings
from peewee import DoesNotExist

router = APIRouter()

@router.post("/register", response_model=UserCreate)
async def register(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    new_user = User.create(username=user.username, email=user.email, password=hashed_password)
    return new_user

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = User.get(User.username == form_data.username)
    except DoesNotExist:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

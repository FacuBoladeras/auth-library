from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from peewee import DoesNotExist
from datetime import timedelta
from .schemas import UserCreate, UserLogin, Token, UserRead
from .models import User
from .utils import get_password_hash, verify_password, create_access_token
from .config import settings
import requests 
from passlib.context import CryptContext


router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Configura el contexto para bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    try:
        user = User.get(User.username == username)
    except DoesNotExist:
        raise credentials_exception
    return user

@router.post("/auth/register", response_model=UserRead)
def register_user(user: UserCreate):
    # Verificar si el usuario ya está registrado en la base de datos de Auth
    if User.select().where(User.username == user.username).exists():
        raise HTTPException(status_code=400, detail="Username already registered")
    if User.select().where(User.email == user.email).exists():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password before saving it
    hashed_password = hash_password(user.password)
    db_user = User.create(username=user.username, email=user.email, password=hashed_password)
    
    # Sincronización con la API de Library
    library_api_url = "http://localhost:8000/customerP/"
    response = requests.post(library_api_url, json={
        "username": user.username,
        "email": user.email,
        "password": hashed_password
    })
    if response.status_code == 400:
        raise HTTPException(status_code=400, detail="Customer already registered in library")
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Could not create customer in library")
    
    return db_user

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

@router.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

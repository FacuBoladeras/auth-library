from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jose import JWTError, jwt
from peewee import DoesNotExist
from datetime import timedelta
from .schemas import UserCreate, Token, UserRead
from .models import User
from .utils import get_password_hash, verify_password, create_access_token, verify_token, hash_password, authenticate_user
from .config import settings
import requests 
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
import httpx
from typing import List


router = APIRouter()

# Configura el contexto para bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory="app/templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("form.html", {
        "request": request,
        "title": "Login",
        "action_url": "/auth/login",
        "button_text": "Login"
    })

@router.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        user = User.get(User.username == username)
    except User.DoesNotExist:
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Login",
            "action_url": "/auth/login",
            "button_text": "Login",
            "error": "Invalid username or password"
        })
    
    if not verify_password(password, user.password):
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Login",
            "action_url": "/auth/login",
            "button_text": "Login",
            "error": "Invalid username or password"
        })
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    
    response = RedirectResponse(url="/auth/show_books", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response
   

@router.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("form.html", {
        "request": request,
        "title": "Register",
        "action_url": "/auth/register",
        "button_text": "Register"
    })

@router.post("/register", response_class=HTMLResponse)
async def register_user(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    if User.select().where(User.username == username).exists():
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Register",
            "action_url": "/auth/register",
            "button_text": "Register",
            "error": "Username already registered"
        })
    if User.select().where(User.email == email).exists():
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Register",
            "action_url": "/auth/register",
            "button_text": "Register",
            "error": "Email already registered"
        })

    hashed_password = hash_password(password)
    db_user = User.create(username=username, email=email, password=hashed_password)
    
    library_api_url = "http://localhost:8001/customerP/"
    response = requests.post(library_api_url, json={
        "username": username,
        "email": email,
        "password": hashed_password
    })

    if response.status_code == 400:
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Register",
            "action_url": "/auth/register",
            "button_text": "Register",
            "error": "Customer already registered in library"
        })
    if response.status_code != 200:
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Register",
            "action_url": "/auth/register",
            "button_text": "Register",
            "error": "Could not create customer in library"
        })
    
    return templates.TemplateResponse("form.html", {
        "request": request,
        "title": "Login",
        "action_url": "/auth/login",
        "button_text": "Login",
        "message": "Registration successful. Please log in."
    })


@router.get("/show_books", response_class=HTMLResponse)
async def show_books_html(request: Request):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8001/auth/GetBooksJ/")
            response.raise_for_status()  # Asegurarse de que se lanza una excepción en caso de un código de estado HTTP de error
            books = response.json()["books"]
        
        # Renderizar el HTML con los datos de los libros
        return templates.TemplateResponse("books.html", {
            "request": request,
            "title": "Books",
            "books": books
        })
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail="Error al obtener los libros de la API de la biblioteca")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Error de conexión: {exc}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

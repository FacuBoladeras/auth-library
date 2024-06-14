from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import JWTError, jwt
from peewee import DoesNotExist
from datetime import timedelta
from .schemas import UserCreate, Token, UserRead
from .models import User
from .utils import get_password_hash, verify_password, create_access_token
from .config import settings
import requests 
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates
import httpx

router = APIRouter()

# Configura el contexto para bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

templates = Jinja2Templates(directory="app/templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

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
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = User.get(User.username == username)
    if user is None:
        raise credentials_exception
    return user


def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    try:
        user = User.get(User.username == username)
    except User.DoesNotExist:
        raise credentials_exception

    return user.username

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


@router.get("/books", response_class=HTMLResponse)
async def get_books(request: Request, current_user: User = Depends(verify_token)):
    try:
        # Obtener el token de la cookie
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        # Eliminar "Bearer " del token
        if token.startswith("Bearer "):
            token = token[len("Bearer "):]

        # Incluir el token en los encabezados de la solicitud a la API de libros
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("http://localhost:8001/noauth/booksF/", headers=headers)
        response.raise_for_status()
        books = response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail="Could not fetch books from library API")

    return templates.TemplateResponse("books.html", {"request": request, "books": books})



@router.get("/show_books", response_class=HTMLResponse)
async def show_books(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8001/noauth/books/")
        books = response.json()

    # Print books to debug
    print(books)

    return templates.TemplateResponse("books.html", {
        "request": request,
        "title": "Books",
        "books": books
    })
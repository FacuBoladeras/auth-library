from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from datetime import timedelta
from typing import List
import requests
import httpx
from fastapi.security import OAuth2PasswordRequestForm
from .models import User, UserDeleteRequest
from .utils import (
    hash_password, verify_password, create_access_token,
    authenticate_user, get_current_active_user
)
from .schemas import Token, UserCreate, UserRead, UserLogin, UserUpdateRequest # Actualiza las importaciones
from .config import settings
from pydantic import BaseModel



router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



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
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse("form.html", {
            "request": request,
            "title": "Login",
            "action_url": "/auth/login",
            "button_text": "Login",
            "error": "Invalid username or password"
        })

    # Obtener el token de acceso haciendo una solicitud POST a /auth/token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "http://localhost:8000/auth/token",
            data={"username": username, "password": password}
        )
        token_response.raise_for_status()
        token_data = Token(**token_response.json())
        access_token = token_data.access_token

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
    User.create(username=username, email=email, password=hashed_password)

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
        # Obtener el token de la cookie
        token = request.cookies.get("access_token")
        print(token)
        if not token:
            raise HTTPException(status_code=401, detail="No access token found")

        # Extraer solo el token sin el prefijo "Bearer "
        token_value = token.replace("Bearer ", "")
        
        async with httpx.AsyncClient() as client:
            books_response = await client.get(f"http://localhost:8001/auth/GetBooksJ/?token={token_value}")
            books_response.raise_for_status()
            books = books_response.json()

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





@router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(username: str):
    user = User.get_or_none(User.username == username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.delete_instance()

    return {"detail": "User deleted successfully"}



@router.put("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def update_user(username: str, user_update: UserUpdateRequest):
    user = User.get_or_none(User.username == username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.username:
        user.username = user_update.username
    if user_update.email:
        user.email = user_update.email
    user.save()

    return {"detail": "User updated successfully"}
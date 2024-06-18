from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    
class UserRead(BaseModel):
    username: str
    email: EmailStr

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
class User(BaseModel):
    username: str
    email: EmailStr
    disabled: bool | None = None  # Assuming you have a 'disabled' field in your User model

    class Config:
        from_attributes = True
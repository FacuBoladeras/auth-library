from peewee import Model, CharField
from .database import db

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField()


class UserInDB(User):
    hashed_password: str
    
class UserDeleteRequest(BaseModel):
    username: str


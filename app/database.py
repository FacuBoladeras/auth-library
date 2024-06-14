from peewee import MySQLDatabase
from .config import settings

db = MySQLDatabase(
    settings.database_name,
    user=settings.database_user,
    password=settings.database_password,
    host=settings.database_host,
    port=settings.database_port
)

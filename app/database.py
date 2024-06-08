from peewee import MySQLDatabase
from .config import settings

db = MySQLDatabase(
    settings.DB_NAME,
    user=settings.DB_USER,
    password=settings.DB_PASSWORD,
    host=settings.DB_HOST,
    port=settings.DB_PORT
)

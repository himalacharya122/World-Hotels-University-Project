# config.py
import os

class Config:
    SECRET_KEY = os.urandom(24)
    
    # MySQL configurations
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'Himal5221@'
    MYSQL_DB = 'world_hotel_final_project_db'
    MYSQL_CURSORCLASS = 'DictCursor'

import os

class Config:
    DEBUG = False
    DB_PATH = "vault.db"

class DevelopmentConfig(Config):
    DEBUG = True
    DB_PATH = "dev_vault.db"

class ProductionConfig(Config):
    DEBUG = False
    DB_PATH = "vault.db"

# Выбор среды через переменную окружения
env = os.environ.get("APP_ENV", "dev")
config = DevelopmentConfig() if env == "dev" else ProductionConfig()
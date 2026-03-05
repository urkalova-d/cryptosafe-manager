import os

class Config:
    DEBUG = False
    DB_PATH = "vault.db"
    DB_VERSION = 1
    AUTO_LOCK_TIMEOUT = 300

class DevelopmentConfig(Config):
    DEBUG = True
    DB_PATH = "dev_vault.db"

class ProductionConfig(Config):
    DEBUG = False
    DB_PATH = "vault.db"

# Логика выбора конфига
env = os.getenv("APP_ENV", "dev")
config = DevelopmentConfig() if env == "dev" else ProductionConfig()
import os
import secrets
import logging
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # API Settings
    PROJECT_NAME: str = "WAF Dashboard API"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    # Log Parsing Directory
    LOG_DIR: str = "/var/log/modsecurity/audit"

    # Security
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    class Config:
        case_sensitive = True
        env_file = ".env"

    def get_secret(self) -> str:
        if self.JWT_SECRET_KEY:
            return self.JWT_SECRET_KEY

        # Fallback to file (e.g. Docker swarm secret)
        if os.path.exists("jwt_secret.txt"):
            with open("jwt_secret.txt", "r") as f:
                return f.read().strip()

        # Fallback to random generation, but log a severe warning
        logging.warning("Generating ephemeral secret for JWT. Instance-isolated!")
        return secrets.token_hex(32)


settings = Settings()
settings.JWT_SECRET_KEY = settings.get_secret()

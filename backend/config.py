import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

# Root directory of the project where .env is located
ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE_PATH = ROOT_DIR / ".env"


class Settings(BaseSettings):
    # Application Configuration
    PROJECT_NAME: str = "Project-CHIMERA"
    ENVIRONMENT: str = "development"
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 3000

    # Database Configuration
    POSTGRES_USER: str = "chimera_admin"
    POSTGRES_PASSWORD: str = "chimera_secret_pass"
    POSTGRES_DB: str = "chimera_soc"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql+asyncpg://chimera_admin:chimera_secret_pass@localhost:5432/chimera_soc"

    # External Services & API Keys
    LYZR_API_KEY: Optional[str] = None
    TAVILY_API_KEY: Optional[str] = None
    SWYTCHCODE_API_KEY: Optional[str] = None
    N8N_WEBHOOK_URL: Optional[str] = "http://localhost:5678/webhook/chimera"
    N8N_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH) if ENV_FILE_PATH.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def async_database_url(self) -> str:
        """Ensure database URL has the asyncpg dialect prefix."""
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


# Singleton instance
settings = Settings()

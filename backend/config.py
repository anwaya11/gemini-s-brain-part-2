import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict

# Root directory of the project and backend directory
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent

# Explicitly load .env files with python-dotenv
if (ROOT_DIR / ".env").exists():
    load_dotenv(ROOT_DIR / ".env", override=False)
if (BACKEND_DIR / ".env").exists():
    load_dotenv(BACKEND_DIR / ".env", override=False)

ENV_FILES = [
    p for p in (ROOT_DIR / ".env", BACKEND_DIR / ".env") if p.exists()
]


class Settings(BaseSettings):
    # Application Configuration
    PROJECT_NAME: str = "Project-CHIMERA"
    ENVIRONMENT: str = "development"
    BACKEND_PORT: int = Field(default=8000, validation_alias=AliasChoices("PORT", "BACKEND_PORT"))
    FRONTEND_PORT: int = 3000

    # Database Configuration
    POSTGRES_USER: str = "chimera_admin"
    POSTGRES_PASSWORD: str = "chimera_secret_pass"
    POSTGRES_DB: str = "chimera_soc"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql+asyncpg://chimera_admin:chimera_secret_pass@localhost:5432/chimera_soc"

    # External Services & API Keys with Safe Fallbacks
    DEMO_MODE: Optional[bool] = None
    LYZR_API_KEY: Optional[str] = "sk-default-kJTAU1T7g3W6xnZrLfXg4w6Tyxw1B4mA"
    TAVILY_API_KEY: Optional[str] = "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"
    SWYTCHCODE_API_KEY: Optional[str] = "swy_key_c44a653be2d52e3bc2a5933f8da2f01eb688b9c66433c1890fa5776462875db4"
    N8N_WEBHOOK_URL: Optional[str] = "https://anwaya.app.n8n.cloud/webhook/162f577a-ccbe-4750-b04a-d554d6faed7e"
    N8N_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-20b"

    model_config = SettingsConfigDict(
        env_file=[str(p) for p in ENV_FILES] if ENV_FILES else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def async_database_url(self) -> str:
        """Ensure database URL has the asyncpg dialect prefix."""
        url = self.DATABASE_URL
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


# Singleton instance
settings = Settings()

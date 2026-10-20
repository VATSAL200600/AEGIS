"""AEGIS Configuration Module"""
import os
from pathlib import Path
from typing import List, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "AEGIS"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "AI-Powered Attack Surface Management Platform"
    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    # SQLite by default, can be overridden by PostgreSQL URL
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'aegis.db'}"

    # External Threat Intel & AI Keys
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Scanning Parameters
    MAX_CONCURRENT_SCANS: int = 3
    DNS_TIMEOUT: float = 5.0
    PORT_SCAN_TIMEOUT: float = 1.5
    PORT_SCAN_CONCURRENCY: int = 50
    DNS_WORDLIST_SIZE: int = 500

    # Demo Mode
    DEMO_MODE: bool = False

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # AI / ML Model Artifact Paths
    RISK_MODEL_PATH: str = str(BASE_DIR / "app" / "ai" / "risk_model.json")
    EXPLAINER_PATH: str = str(BASE_DIR / "app" / "ai" / "explainer.pkl")

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

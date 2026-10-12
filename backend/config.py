import ipaddress
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Agent Tiger - Active Directory Security Investigation API"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Authorized Network Scope
    AUTHORIZED_SCOPE_CIDR: str = "192.168.56.0/24"

    # Database Configuration (Defaults to local PostgreSQL, fall back to SQLite for local development/tests)
    DATABASE_URL: str = "sqlite:///./agent_tiger.db"

    # External Services
    OLLAMA_ENDPOINT: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"

    # CORS settings (allowed origins for React/Vite development server)
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def is_target_in_scope(self, ip_str: str) -> bool:
        """Enforces that target IP belongs strictly to authorized lab scope."""
        try:
            target_ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(self.AUTHORIZED_SCOPE_CIDR)
            return target_ip in network
        except ValueError:
            return False


settings = Settings()

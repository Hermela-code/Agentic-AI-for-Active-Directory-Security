import ipaddress
import socket
from typing import List, Optional, Union
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Active Directory Security Investigation API"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Authorized Network Scopes: Comma-separated list of subnets/CIDRs or domains.
    # Leave empty ("") to allow any target without subnet boundary enforcement.
    # Example for .env: AUTHORIZED_SCOPES="10.0.0.0/8,172.16.0.0/12,ad.corporate.internal"
    AUTHORIZED_SCOPES: str = ""
    # Optional single CIDR scope (legacy env var)
    AUTHORIZED_SCOPE_CIDR: str = ""

    # Flag to explicitly enable or disable strict scope boundaries
    ENFORCE_SCOPE_CHECK: bool = True

    # Database Configuration
    DATABASE_URL: str = "sqlite:///./agent_tiger.db"

    # External LLM Services
    OLLAMA_ENDPOINT: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"

    # Allowed Web Origins for UI Integration
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

    def get_authorized_networks(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Parses defined CIDR strings and legacy CIDR into IP network objects."""
        entries = []
        if self.AUTHORIZED_SCOPES.strip():
            entries.extend([e.strip() for e in self.AUTHORIZED_SCOPES.split(",") if e.strip()])
        if self.AUTHORIZED_SCOPE_CIDR.strip():
            entries.append(self.AUTHORIZED_SCOPE_CIDR.strip())
        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                # Ignore invalid entries (could be domains)
                continue
        return networks

    def is_target_in_scope(self, target_str: str) -> bool:
        """
        Validates target reachability and boundary enforcement.
        If ENFORCE_SCOPE_CHECK is False or AUTHORIZED_SCOPES is empty,
        all valid IP addresses and resolvable hostnames are permitted.
        """
        cleaned_target = target_str.strip()
        if not cleaned_target:
            return False

        # Attempt DNS resolution if target is an FQDN/hostname
        resolved_ip = cleaned_target
        try:
            resolved_ip = socket.gethostbyname(cleaned_target)
        except (socket.gaierror, UnicodeError):
            pass

        # Verify that the target is a syntactically valid IP address
        try:
            target_ip = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False

        # If scope enforcement is disabled, any valid IP/host is permitted
        if not self.ENFORCE_SCOPE_CHECK:
            return True
        # If no scopes are defined, permissive behavior
        if not (self.AUTHORIZED_SCOPES.strip() or self.AUTHORIZED_SCOPE_CIDR.strip()):
            return True
        # Check against authorized networks
        networks = self.get_authorized_networks()
        return any(target_ip in net for net in networks)


settings = Settings()
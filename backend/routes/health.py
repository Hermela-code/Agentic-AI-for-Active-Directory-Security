import urllib.request
import urllib.error
from fastapi import APIRouter
from backend.config import settings

router = APIRouter(prefix="/health", tags=["System Health"])


@router.get("")
def health_check():
    """
    Checks backend service status and external dependency connectivity.
    """
    ollama_ok = False
    try:
        req = urllib.request.Request(f"{settings.OLLAMA_ENDPOINT}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                ollama_ok = True
    except Exception:
        ollama_ok = False

    # Safely retrieve scope, prioritizing AUTHORIZED_SCOPES
    scope = getattr(
        settings, 
        "AUTHORIZED_SCOPES", 
        getattr(settings, "AUTHORIZED_SCOPE_CIDR", "unrestricted")
    )

    return {
        "status": "healthy",
        "version": settings.VERSION,
        "authorized_scope": scope,
        "services": {
            "api": "online",
            "ollama": "online" if ollama_ok else "offline"
        }
    }
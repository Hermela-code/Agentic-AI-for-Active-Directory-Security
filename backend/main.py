from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import engine, Base
from backend.routes import health, investigations, approvals

# Ensure all database tables exist on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend orchestration service and persistence layer for Agent Tiger Active Directory security assessments.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Build a comprehensive origin whitelist to support localhost, 127.0.0.1, and custom configs
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# Merge any custom origins configured in settings
if hasattr(settings, "CORS_ORIGINS") and settings.CORS_ORIGINS:
    for origin in settings.CORS_ORIGINS:
        if origin not in allowed_origins:
            allowed_origins.append(origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register endpoints under /api
app.include_router(health.router, prefix=settings.API_PREFIX)
app.include_router(investigations.router, prefix=settings.API_PREFIX)
app.include_router(approvals.router, prefix=settings.API_PREFIX)


@app.get("/")
def root():
    return {
        "message": "Agent Tiger API is running.",
        "documentation": "/docs",
        "health": f"{settings.API_PREFIX}/health"
    }
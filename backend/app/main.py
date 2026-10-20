"""AEGIS -- FastAPI Application Entry Point

Configures the FastAPI app with CORS middleware, lifespan hooks for
database initialization, and mounts all API routers.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: initialize DB on startup, clean up on shutdown."""
    logger.info("AEGIS starting up - initializing database tables...")
    init_db()
    logger.info("Database initialized successfully")
    yield
    logger.info("AEGIS shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ---- CORS Middleware ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- Global Exception Handler ----
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": str(exc) if settings.DEBUG else None,
            }
        },
    )


# ---- Register API Routers ----
from app.api.scans import router as scans_router
from app.api.assets import router as assets_router
from app.api.dashboard import router as dashboard_router
from app.api.events import router as events_router
from app.api.reports import router as reports_router

app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(reports_router)


# ---- Health Check ----
@app.get("/api/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }

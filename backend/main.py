import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.routers.ws import router as ws_router
from backend.routers.ingest import router as ingest_router, edge_filter
from backend.deception.decoy_routes import decoy_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    - Startup: Pre-load XGBoost model, verify DB connectivity.
    - Shutdown: Graceful cleanup.
    """
    # ── Startup ───────────────────────────────────────────────────────
    print(f"[CHIMERA] Starting {settings.PROJECT_NAME} ({settings.ENVIRONMENT})")
    print(f"[CHIMERA] Backend port: {settings.BACKEND_PORT}")

    # Pre-load XGBoost model and scaler
    if edge_filter.model is not None:
        print("[CHIMERA] XGBoost EdgeFilter model loaded [OK]")
    else:
        print("[CHIMERA] WARNING: XGBoost model not found - running with heuristic fallback")

    # Verify DB connectivity
    try:
        from backend.db.postgres import engine
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        print("[CHIMERA] PostgreSQL connection verified [OK]")
    except Exception as e:
        print(f"[CHIMERA] WARNING: PostgreSQL not reachable - {e}")
        print("[CHIMERA] Server will start, but DB operations will fail until Postgres is available")

    print("[CHIMERA] All systems initialized - server ready")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────
    print("[CHIMERA] Shutting down gracefully...")
    try:
        from backend.db.postgres import engine
        await engine.dispose()
        print("[CHIMERA] Database engine disposed [OK]")
    except Exception:
        pass


# ── FastAPI App ───────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="CHIMERA SOC — Autonomous Security Operations Center powered by multi-agent AI",
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS Middleware ───────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register Routers ─────────────────────────────────────────────────────
app.include_router(ingest_router, tags=["Ingest"])
app.include_router(ws_router, tags=["WebSocket"])
app.include_router(decoy_router, tags=["Deception"])


# ── Health Check ──────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Basic health/readiness probe."""
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
    }

import json
import logging
import re
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from app.api import admin, algorithms, auth, cameras, dashboard, edge, events, faces, media, persons, realtime, system
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, engine, get_db
from app.schemas import HealthResponse
from app.seed import seed_database
from app.services.metrics import render_prometheus_metrics, request_latency

settings = get_settings()
logger = logging.getLogger("mineguard.api")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def safe_request_id(value: str | None) -> str:
    return value if value and REQUEST_ID_PATTERN.fullmatch(value) else str(uuid4())


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.environment in {"development", "test"}:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            seed_database(db)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="矿井生产智能视频监控平台 API",
    lifespan=lifespan,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(OperationalError)
@app.exception_handler(SQLAlchemyTimeoutError)
async def database_temporarily_unavailable(
    _: Request, __: OperationalError | SQLAlchemyTimeoutError
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "数据库暂时不可用，系统正在自动恢复"},
        headers={"Retry-After": "2"},
    )


@app.middleware("http")
async def operational_headers(request: Request, call_next):
    request_id = safe_request_id(request.headers.get("X-Request-ID"))
    started = perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        elapsed_ms = (perf_counter() - started) * 1000
        request_latency.observe(elapsed_ms)
        logger.error(
            json.dumps(
                {
                    "event": "api_request_failed",
                    "request_id": request_id[:128],
                    "method": request.method,
                    "path": request.url.path,
                    "error_type": type(exc).__name__,
                    "elapsed_ms": round(elapsed_ms, 1),
                },
                separators=(",", ":"),
            )
        )
        raise
    elapsed_ms = (perf_counter() - started) * 1000
    request_latency.observe(elapsed_ms)
    response.headers["X-Request-ID"] = request_id[:128]
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"
    if response.status_code >= 500:
        logger.error(
            json.dumps(
                {
                    "event": "api_server_error",
                    "request_id": request_id[:128],
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "elapsed_ms": round(elapsed_ms, 1),
                },
                separators=(",", ":"),
            )
        )
    return response


for router in [auth.router, dashboard.router, cameras.router, events.router, realtime.router, edge.router, persons.router, faces.router, media.router, algorithms.router, admin.router, system.router]:
    app.include_router(router, prefix=settings.api_prefix)


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="mineguard-api", version="0.1.0")


@app.get("/ready", response_model=HealthResponse, tags=["system"])
def readiness(db: Session = Depends(get_db)) -> HealthResponse:
    db.execute(text("SELECT 1"))
    return HealthResponse(status="ready", service="mineguard-api", version="0.1.0")


@app.get("/internal/metrics", include_in_schema=False)
def operational_metrics(db: Session = Depends(get_db)) -> Response:
    return Response(
        render_prometheus_metrics(db, settings),
        media_type="text/plain; version=0.0.4",
    )

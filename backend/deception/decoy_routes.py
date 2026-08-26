"""
backend/deception/decoy_routes.py

Honeypot / deception layer — FastAPI router that catches all traffic
directed at /decoy/* paths and responds with convincing-but-fake content
designed to waste an attacker's time and gather intelligence.

Decoy personas:
  /decoy/db-admin          → fake database admin panel (SQL errors, table dumps)
  /decoy/ssh-login         → fake SSH/auth endpoint
  /decoy/internal-api/*    → fake internal REST API with synthetic users/tokens
  /decoy/config            → fake app configuration dump
  /decoy/health-internal   → fake internal health/metrics endpoint
  /decoy/<anything else>   → generic 500 + fake stack trace

All responses intentionally leak plausible-but-fabricated data so that
attackers burn time on dead ends while their activity is logged.
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

decoy_router = APIRouter(tags=["Deception"])

# ---------------------------------------------------------------------------
# Helpers — synthetic data generators
# ---------------------------------------------------------------------------

_FAKE_USERS = [
    {"id": 1, "username": "admin",       "role": "superadmin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    {"id": 2, "username": "db_service",  "role": "dba",        "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
    {"id": 3, "username": "chimera_svc", "role": "service",    "password_hash": "25d55ad283aa400af464c76d713c07ad"},
    {"id": 4, "username": "monitor",     "role": "readonly",   "password_hash": "098f6bcd4621d373cade4e832627b4f6"},
]

_FAKE_TABLES = [
    "users", "sessions", "credentials", "audit_log",
    "api_keys", "payment_methods", "internal_tokens",
]

_FAKE_DB_ERRORS = [
    "ERROR:  relation \"users\" does not exist",
    "ERROR:  syntax error at or near \"SELECT\"",
    "ERROR:  permission denied for table credentials",
    "FATAL:  role \"postgres\" does not exist",
    "ERROR:  column \"password\" of relation \"users\" does not exist",
    "ERROR:  deadlock detected\nDETAIL:  Process 14821 waits for ShareLock on transaction 1234",
]

_FAKE_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
    "SSH-2.0-OpenSSH_9.0p1",
]

_FAKE_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIiwiZXhwIjoxNzk5OTk5OTk5fQ.FAKE_SIGNATURE_DO_NOT_USE",
    "sk-internal-7f3a9d2e1b4c8f6a0e5d3b1c9a7f2e4d",
    "Bearer ghp_fake1234567890abcdefghijklmnopqrst",
]


def _deterministic_rng(seed: str) -> random.Random:
    """A seeded RNG so the same path always returns the same fake data."""
    digest = int(hashlib.md5(seed.encode()).hexdigest(), 16)
    return random.Random(digest)


def _fake_timestamp(rng: random.Random, days_back: int = 30) -> str:
    delta = timedelta(seconds=rng.randint(0, days_back * 86400))
    return (datetime.now(timezone.utc) - delta).isoformat()


def _slow_response(min_ms: int = 200, max_ms: int = 800) -> None:
    """Simulate a slow server to waste attacker time."""
    time.sleep(random.uniform(min_ms / 1000, max_ms / 1000))


# ---------------------------------------------------------------------------
# Response builders per decoy persona
# ---------------------------------------------------------------------------

def _db_admin_response(path: str, method: str, rng: random.Random) -> JSONResponse:
    """Fake database admin panel — returns SQL errors + fake table dumps."""
    if method == "POST":
        # Simulate a failed SQL query attempt
        error = rng.choice(_FAKE_DB_ERRORS)
        return JSONResponse(
            status_code=500,
            content={
                "error": "DatabaseError",
                "message": error,
                "query_id": str(uuid.UUID(int=rng.getrandbits(128))),
                "db_host": "chimera-db-primary.internal:5432",
                "db_name": "chimera_soc",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    # GET — return fake table schema + sample rows
    table = rng.choice(_FAKE_TABLES)
    rows = [
        {
            "id": i,
            "username": rng.choice([u["username"] for u in _FAKE_USERS]),
            "created_at": _fake_timestamp(rng),
            "last_login": _fake_timestamp(rng, days_back=7),
            "is_active": rng.choice([True, True, True, False]),
        }
        for i in range(1, rng.randint(3, 8))
    ]
    return JSONResponse(
        status_code=200,
        content={
            "database": "chimera_soc",
            "table": table,
            "total_rows": rng.randint(1500, 50000),
            "page": 1,
            "rows": rows,
            "schema": {
                "id": "integer PRIMARY KEY",
                "username": "varchar(64) NOT NULL",
                "created_at": "timestamptz DEFAULT now()",
                "last_login": "timestamptz",
                "is_active": "boolean DEFAULT true",
            },
        },
    )


def _ssh_login_response(method: str, rng: random.Random) -> Any:
    """Fake SSH/brute-force endpoint."""
    if method == "POST":
        # Always "fail" after a delay (to slow down brute force)
        _slow_response(300, 1200)
        return JSONResponse(
            status_code=401,
            content={
                "error": "AuthenticationFailed",
                "message": "Permission denied (publickey,password).",
                "banner": rng.choice(_FAKE_SSH_BANNERS),
                "attempts_remaining": rng.randint(0, 2),
                "lockout_seconds": rng.randint(30, 300),
            },
        )

    return JSONResponse(
        status_code=200,
        content={
            "service": "ssh",
            "banner": rng.choice(_FAKE_SSH_BANNERS),
            "auth_methods": ["password", "publickey"],
            "host_key_fingerprint": "SHA256:" + hashlib.sha256(
                rng.randbytes(32)
            ).hexdigest()[:43],
        },
    )


def _internal_api_response(sub_path: str, rng: random.Random) -> JSONResponse:
    """Fake internal REST API with synthetic users, tokens, and telemetry."""
    if "token" in sub_path or "auth" in sub_path:
        return JSONResponse(
            status_code=200,
            content={
                "access_token": rng.choice(_FAKE_TOKENS),
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "admin:read admin:write",
            },
        )

    if "user" in sub_path:
        users = [
            {**u, "last_seen": _fake_timestamp(rng, 7), "mfa_enabled": rng.choice([True, False])}
            for u in _FAKE_USERS
        ]
        return JSONResponse(status_code=200, content={"users": users, "total": len(users)})

    if "telemetry" in sub_path or "metric" in sub_path:
        return JSONResponse(
            status_code=200,
            content={
                "cpu_usage": round(rng.uniform(12, 88), 2),
                "memory_mb": rng.randint(512, 8192),
                "active_sessions": rng.randint(1, 45),
                "requests_per_sec": round(rng.uniform(50, 500), 1),
                "uptime_seconds": rng.randint(86400, 2592000),
                "hostname": "chimera-app-01.internal",
            },
        )

    # Generic internal endpoint
    return JSONResponse(
        status_code=200,
        content={
            "service": "chimera-internal-api",
            "version": "3.2.1",
            "environment": "production",
            "node_id": str(uuid.UUID(int=rng.getrandbits(128))),
            "cluster": "us-east-1a",
        },
    )


def _config_response(rng: random.Random) -> JSONResponse:
    """Fake configuration dump — enticing but entirely fabricated."""
    return JSONResponse(
        status_code=200,
        content={
            "database": {
                "host": "chimera-db-primary.internal",
                "port": 5432,
                "name": "chimera_soc",
                "user": "chimera_admin",
                "password": "ch1m3r@_s3cr3t_2024!",   # fake — bait for credential stuffers
                "ssl_mode": "require",
            },
            "redis": {"host": "chimera-cache.internal", "port": 6379, "db": 0},
            "jwt_secret": "3d6f44e7a1b9c2d8e5f0a3b7c4e1d9f2a8b5c6e3d0f7a4b1c8e5d2f9a6b3c0",
            "internal_api_key": rng.choice(_FAKE_TOKENS),
            "aws_region": "us-east-1",
            "s3_bucket": "chimera-logs-prod-internal",
        },
    )


def _health_internal_response(rng: random.Random) -> JSONResponse:
    """Fake internal health/metrics endpoint."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "checks": {
                "database": "ok",
                "redis": "ok",
                "message_queue": "ok",
                "ml_service": "degraded",   # slight imperfection to look realistic
            },
            "version": "3.2.1-build.8821",
            "git_sha": hashlib.sha1(rng.randbytes(20)).hexdigest(),
            "started_at": _fake_timestamp(rng, days_back=7),
        },
    )


def _generic_error_response(path: str, rng: random.Random) -> PlainTextResponse:
    """Catch-all: generic 500 with a convincing fake Python stack trace."""
    err_id = str(uuid.UUID(int=rng.getrandbits(128)))
    trace = (
        f"Traceback (most recent call last):\n"
        f'  File "/opt/chimera/backend/app/core/router.py", line 214, in dispatch\n'
        f"    response = await call_next(request)\n"
        f'  File "/opt/chimera/backend/app/middleware/auth.py", line 88, in __call__\n'
        f"    user = await verify_token(token)\n"
        f'  File "/opt/chimera/backend/app/services/auth_service.py", line 52, in verify_token\n'
        f"    row = await db.fetchrow(query, token_hash)\n"
        f"asyncpg.exceptions.PostgresConnectionError: could not connect to server: "
        f"Connection refused\n"
        f"\tIs the server running on host \"chimera-db-primary.internal\" (10.0.1.42) "
        f"and accepting TCP/IP connections on port 5432?\n\n"
        f"error_id: {err_id}\n"
        f"path:     {path}\n"
        f"time:     {datetime.now(timezone.utc).isoformat()}\n"
    )
    return PlainTextResponse(content=trace, status_code=500)


# ---------------------------------------------------------------------------
# Catch-all decoy endpoint
# ---------------------------------------------------------------------------

@decoy_router.api_route("/decoy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def decoy_catch_all(path: str, request: Request) -> Any:
    """
    Honeypot catch-all — routes attackers into a convincing deception layer.

    Path personas:
      db-admin          → fake SQL database admin panel
      ssh-login         → fake SSH/auth endpoint (always denies, adds delay)
      internal-api/*    → fake internal REST API (users, tokens, telemetry)
      config            → fake configuration dump with enticing credentials
      health-internal   → fake internal health / metrics endpoint
      <anything else>   → generic 500 + fake Python stack trace
    """
    method = request.method
    rng = _deterministic_rng(path + method)

    # Log the hit (attacker telemetry) — non-blocking
    client_ip = request.client.host if request.client else "unknown"
    print(
        f"[DECOY] Hit: {method} /decoy/{path} | "
        f"ip={client_ip} | "
        f"ua={request.headers.get('user-agent', '-')[:80]}"
    )

    # Route to the appropriate persona
    if path.startswith("db-admin"):
        _slow_response(100, 400)
        return _db_admin_response(path, method, rng)

    if path.startswith("ssh-login"):
        return _ssh_login_response(method, rng)

    if path.startswith("internal-api"):
        sub = path[len("internal-api"):].lstrip("/")
        _slow_response(50, 200)
        return _internal_api_response(sub, rng)

    if path.startswith("config"):
        _slow_response(100, 300)
        return _config_response(rng)

    if path.startswith("health-internal"):
        return _health_internal_response(rng)

    # Default: generic error
    _slow_response(200, 600)
    return _generic_error_response(path, rng)

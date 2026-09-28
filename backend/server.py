"""
REST API for the Security Service dashboard.

Run from the repository root:
    uvicorn backend.server:app --reload --port 8000
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend import core  # noqa: F401  (sets working directory + import path first)
from database import init_db
from secure_messaging import init_secure_messages_table

from backend.routers import auth_routes, dashboard_routes, file_routes, message_routes, security_routes

init_db()
init_secure_messages_table()

app = FastAPI(title="Security Service API", version="1.0.0")

origins = os.environ.get("SECURITY_API_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (auth_routes, dashboard_routes, message_routes, file_routes, security_routes):
    app.include_router(module.router)


@app.get("/api/health")
def health():
    return {"ok": True}


# Serve the built React app (frontend/dist) when it exists, so one process can host both.
DIST = os.path.join(core.ROOT, "frontend", "dist")
if os.path.isdir(DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        candidate = os.path.realpath(os.path.join(DIST, path))
        if path and candidate.startswith(os.path.realpath(DIST) + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(DIST, "index.html"))

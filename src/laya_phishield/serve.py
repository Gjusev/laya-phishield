"""HTTP API: POST an email, get its verdict with reasons.

    uvicorn laya_phishield.serve:app --port 8000
    curl -s localhost:8000/scan -H 'content-type: application/json' \
         -d '{"raw": "<full RFC822 email>"}'

The app factory takes an injected agent so tests run without a checkpoint;
production callers use the lazy default.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from .pipeline import load_head, scan_email

__all__ = ["create_app"]


class ScanRequest(BaseModel):
    raw: str


def create_app(agent=None) -> FastAPI:
    """Build the API app; `agent` defaults to a lazily created laya.Agent."""
    app = FastAPI(
        title="laya-phishield",
        description="Explainable phishing detection: eight atomic signals "
        "plus deterministic flags, combined by a logistic head.",
        version="0.1.0",
    )
    state = {"agent": agent, "head": None}

    def get_agent():
        if state["agent"] is None:
            import laya

            state["agent"] = laya.Agent()
        return state["agent"]

    def get_head():
        if state["head"] is None:
            state["head"] = load_head()
        return state["head"]

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/scan")
    def scan(request: ScanRequest) -> dict:
        verdict = scan_email(get_agent(), get_head(), request.raw)
        return verdict.to_dict()

    return app


def _default_app() -> FastAPI:
    """Module-level app for `uvicorn laya_phishield.serve:app`."""
    return create_app()


app: Optional[FastAPI] = None  # built on first import of `serve` via uvicorn


def __getattr__(name):  # lazy module-level `app` (PEP 562)
    if name == "app":
        global app
        if app is None:
            app = _default_app()
        return app
    raise AttributeError(name)

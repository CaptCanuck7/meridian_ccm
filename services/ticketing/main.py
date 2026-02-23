"""
Meridian — Mock Ticketing Service
Simulates a subset of the ServiceNow Incident Table API.

Supported endpoints:
  POST   /api/now/table/incident          create incident
  GET    /api/now/table/incident          list incidents (filter by sysparm_query)
  GET    /api/now/table/incident/{sys_id} get single incident
  PATCH  /api/now/table/incident/{sys_id} update incident fields

Responses use ServiceNow's standard envelope:
  { "result": <incident | list> }

State codes (ServiceNow standard):
  1 = New  |  2 = In Progress  |  6 = Resolved  |  7 = Closed

Priority codes:
  1 = Critical  |  2 = High  |  3 = Medium  |  4 = Low
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Meridian Mock ServiceNow", version="1.0.0")

# ── In-memory store ───────────────────────────────────────────────────────────
_store: dict[str, dict[str, Any]] = {}
_counter: int = 0
_lock = Lock()


def _next_number() -> str:
    global _counter
    _counter += 1
    return f"INC{_counter:07d}"


def _now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Request / Response models ─────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    short_description: str
    description: str = ""
    state: int = Field(default=1, ge=1, le=7)
    priority: int = Field(default=3, ge=1, le=4)
    category: str = "software"
    assignment_group: str = ""
    assigned_to: str = ""
    caller_id: str = ""
    sys_created_by: str = "meridian-agent"
    # Allow arbitrary extra fields (control metadata, etc.)
    model_config = {"extra": "allow"}


class IncidentUpdate(BaseModel):
    short_description: str | None = None
    description: str | None = None
    state: int | None = Field(default=None, ge=1, le=7)
    priority: int | None = Field(default=None, ge=1, le=4)
    category: str | None = None
    assignment_group: str | None = None
    assigned_to: str | None = None
    caller_id: str | None = None
    model_config = {"extra": "allow"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_record(payload: dict[str, Any]) -> dict[str, Any]:
    now = _now_str()
    sys_id = str(uuid.uuid4())
    return {
        "sys_id": sys_id,
        "number": _next_number(),
        "short_description": payload.get("short_description", ""),
        "description": payload.get("description", ""),
        "state": payload.get("state", 1),
        "priority": payload.get("priority", 3),
        "category": payload.get("category", "software"),
        "assignment_group": payload.get("assignment_group", ""),
        "assigned_to": payload.get("assigned_to", ""),
        "caller_id": payload.get("caller_id", ""),
        "sys_created_by": payload.get("sys_created_by", "meridian-agent"),
        "opened_at": now,
        "sys_updated_on": now,
        # Store any extra control-metadata fields transparently
        **{k: v for k, v in payload.items() if k not in {
            "short_description", "description", "state", "priority",
            "category", "assignment_group", "assigned_to", "caller_id",
            "sys_created_by",
        }},
    }


def _match_query(record: dict[str, Any], sysparm_query: str) -> bool:
    """
    Minimal ServiceNow sysparm_query parser.
    Supports: field=value  joined by ^  (AND logic only).
    Example: state=1^priority=2
    """
    if not sysparm_query:
        return True
    for clause in sysparm_query.split("^"):
        if "=" not in clause:
            continue
        field, _, value = clause.partition("=")
        field = field.strip()
        value = value.strip()
        rec_val = record.get(field)
        # Compare as string to match ServiceNow behaviour
        if str(rec_val) != value:
            return False
    return True


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/now/table/incident", status_code=201)
def create_incident(body: IncidentCreate) -> JSONResponse:
    payload = body.model_dump()
    with _lock:
        record = _build_record(payload)
        _store[record["sys_id"]] = record
    return JSONResponse(status_code=201, content={"result": record})


@app.get("/api/now/table/incident")
def list_incidents(
    sysparm_query: str = Query(default="", alias="sysparm_query"),
    sysparm_limit: int = Query(default=100, alias="sysparm_limit", ge=1, le=1000),
    sysparm_offset: int = Query(default=0, alias="sysparm_offset", ge=0),
) -> dict[str, Any]:
    with _lock:
        all_records = list(_store.values())

    matched = [r for r in all_records if _match_query(r, sysparm_query)]
    # Newest first
    matched.sort(key=lambda r: r["opened_at"], reverse=True)
    page = matched[sysparm_offset: sysparm_offset + sysparm_limit]
    return {"result": page}


@app.get("/api/now/table/incident/{sys_id}")
def get_incident(sys_id: str) -> dict[str, Any]:
    with _lock:
        record = _store.get(sys_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"error": "No Record found", "sys_id": sys_id})
    return {"result": record}


@app.patch("/api/now/table/incident/{sys_id}")
def update_incident(sys_id: str, body: IncidentUpdate) -> dict[str, Any]:
    with _lock:
        record = _store.get(sys_id)
        if record is None:
            raise HTTPException(
                status_code=404, detail={"error": "No Record found", "sys_id": sys_id}
            )
        updates = {k: v for k, v in body.model_dump(exclude_unset=True).items()}
        # Also allow extra fields passed through
        updates.update({k: v for k, v in body.model_extra.items()})
        record.update(updates)
        record["sys_updated_on"] = _now_str()
        _store[sys_id] = record
    return {"result": record}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "meridian-ticketing"}


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "Meridian Mock Ticketing (ServiceNow)",
        "incident_count": len(_store),
        "docs": "/docs",
    }

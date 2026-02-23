"""
PostgreSQL persistence layer.

Responsibilities:
  - ensure_schema()              — idempotent schema creation / migration
  - insert_evidence()            — store signed evidence with Merkle metadata
  - insert_run()                 — store control run result with optional ticket reference
  - get_last_ticket()            — return the most recent ticket number for a control
  - get_evidence_leaf_hashes()   — ordered leaf hashes for Merkle tree reconstruction
  - insert_trust_envelope()      — store a signed TrustEnvelope with its Claims
  - get_trust_envelopes()        — load trust envelopes for the dashboard
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)

# ── Schema ─────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS evidence (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id       TEXT        NOT NULL,
    check_name       TEXT        NOT NULL,
    collected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collector        TEXT        NOT NULL DEFAULT 'meridian-agent',
    raw_data         JSONB       NOT NULL,
    signature        TEXT        NOT NULL,
    merkle_leaf_hash TEXT,
    merkle_index     INTEGER
);

CREATE TABLE IF NOT EXISTS control_runs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id    TEXT        NOT NULL,
    run_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status        TEXT        NOT NULL CHECK (status IN ('pass', 'fail', 'error')),
    evidence_id   UUID        REFERENCES evidence(id),
    summary       JSONB,
    ticket_number TEXT,
    ticket_sys_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_control_runs_control_id
    ON control_runs (control_id, run_at DESC);

CREATE TABLE IF NOT EXISTS trust_envelopes (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    envelope_id          TEXT        NOT NULL,
    control_id           TEXT        NOT NULL,
    product_id           TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trust_level          TEXT        NOT NULL,
    composite_confidence FLOAT       NOT NULL,
    merkle_root          TEXT,
    envelope_data        JSONB       NOT NULL,
    signature            TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trust_envelopes_control_product
    ON trust_envelopes (control_id, product_id, created_at DESC);
"""

# Migrations: add columns to existing tables when upgrading from earlier schema
_MIGRATIONS = [
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS merkle_leaf_hash TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS merkle_index INTEGER",
]


def ensure_schema(conn: "psycopg2.connection") -> None:
    with conn.cursor() as cur:
        cur.execute(_DDL)
        for migration in _MIGRATIONS:
            try:
                cur.execute(migration)
            except Exception as exc:
                log.warning("Migration skipped (%s): %s", migration[:60], exc)
    conn.commit()
    log.info("DB schema ready.")


# ── Evidence writes ─────────────────────────────────────────────────────────────

def insert_evidence(
    conn: "psycopg2.connection",
    control_id: str,
    check_name: str,
    raw_data: dict[str, Any],
    signature: str,
    merkle_leaf_hash: str | None = None,
    merkle_index: int | None = None,
) -> str:
    """Insert evidence row and return its UUID."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO evidence
                (control_id, check_name, raw_data, signature,
                 merkle_leaf_hash, merkle_index)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                control_id,
                check_name,
                json.dumps(raw_data),
                signature,
                merkle_leaf_hash,
                merkle_index,
            ),
        )
        evidence_id = str(cur.fetchone()[0])
    conn.commit()
    return evidence_id


def insert_run(
    conn: "psycopg2.connection",
    control_id: str,
    status: str,
    evidence_id: str,
    summary: dict[str, Any],
    ticket_number: str | None = None,
    ticket_sys_id: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO control_runs
                (control_id, status, evidence_id, summary, ticket_number, ticket_sys_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                control_id,
                status,
                evidence_id,
                json.dumps(summary),
                ticket_number,
                ticket_sys_id,
            ),
        )
    conn.commit()


# ── Trust envelope writes ──────────────────────────────────────────────────────

def insert_trust_envelope(
    conn: "psycopg2.connection",
    envelope: Any,             # TrustEnvelope instance
) -> str:
    """Persist a signed TrustEnvelope and return its DB UUID."""
    d = envelope.to_dict()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO trust_envelopes
                (envelope_id, control_id, product_id, trust_level,
                 composite_confidence, merkle_root, envelope_data, signature)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                d["envelope_id"],
                d["control_id"],
                d["product_id"],
                d["trust_level"],
                d["composite_confidence"],
                d.get("evidence_summary", {}).get("merkle_root"),
                json.dumps(d),
                d["signature"],
            ),
        )
        db_id = str(cur.fetchone()[0])
    conn.commit()
    return db_id


# ── Reads ──────────────────────────────────────────────────────────────────────

def get_last_ticket(conn: "psycopg2.connection", control_id: str) -> str | None:
    """Return the most recent ticket_number for this control, or None."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT ticket_number
            FROM   control_runs
            WHERE  control_id    = %s
              AND  ticket_number IS NOT NULL
            ORDER BY run_at DESC
            LIMIT 1
            """,
            (control_id,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def get_evidence_leaf_hashes(conn: "psycopg2.connection") -> list[str]:
    """
    Return all Merkle leaf hashes ordered by merkle_index, for Merkle tree
    reconstruction on agent startup.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT merkle_leaf_hash
            FROM   evidence
            WHERE  merkle_leaf_hash IS NOT NULL
            ORDER BY merkle_index ASC
            """,
        )
        rows = cur.fetchall()
    return [row[0] for row in rows]


def get_trust_envelopes(
    conn: "psycopg2.connection",
    limit: int = 500,
) -> list[dict]:
    """Load the most recent trust envelopes for the dashboard."""
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(
            """
            SELECT envelope_id, control_id, product_id, created_at,
                   trust_level, composite_confidence, merkle_root,
                   envelope_data, signature
            FROM   trust_envelopes
            ORDER  BY created_at DESC
            LIMIT  %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    return [dict(r) for r in rows]

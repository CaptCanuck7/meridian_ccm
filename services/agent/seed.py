"""
Meridian demo seed script
==========================
Populates Keycloak and Postgres with realistic demo data.

Run once after the stack is up:
  docker exec meridian-agent python seed.py

Idempotent: skips Keycloak users/attributes that already exist, and skips
the Postgres insert if historical rows are already present.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("seed")

# ── Config ────────────────────────────────────────────────────────────────────

KEYCLOAK_URL        = os.getenv("KEYCLOAK_URL",        "http://keycloak:8080")
KEYCLOAK_ADMIN      = os.getenv("KEYCLOAK_ADMIN",       "admin")
KEYCLOAK_ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS",  "admin")
TICKETING_URL       = os.getenv("TICKETING_URL",        "http://ticketing:8001")
POSTGRES_DSN        = os.getenv("POSTGRES_DSN",         "postgresql://meridian:meridian@postgres:5432/meridian")
KEY_DIR             = os.getenv("KEY_DIR",              "/keys")
REALM               = "master"

NOW = datetime.now(timezone.utc)


# ── Signing (Ed25519) ─────────────────────────────────────────────────────────

from crypto.keys import KeyPair as _KeyPair

_key_pair: _KeyPair = _KeyPair.load_or_generate(
    private_path=os.path.join(KEY_DIR, "signing_key.pem"),
    public_path=os.path.join(KEY_DIR, "signing_key.pub.pem"),
)


def sign(payload: dict) -> str:
    return _key_pair.sign(payload)


# ── Keycloak helpers ──────────────────────────────────────────────────────────

def kc_token() -> str:
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": KEYCLOAK_ADMIN, "password": KEYCLOAK_ADMIN_PASS},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def kc_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def kc_list_users(token: str) -> list[dict]:
    r = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?max=500",
        headers=kc_headers(token), timeout=10,
    )
    r.raise_for_status()
    return r.json()


def kc_upsert_user(token: str, user: dict, existing: dict[str, str]) -> str:
    """Create or update user; always applies attributes. Returns user ID."""
    username = user["username"]
    if username in existing:
        uid = existing[username]
        # Always PUT the full user representation so attributes are applied
        r = requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{uid}",
            headers=kc_headers(token), json=user, timeout=10,
        )
        r.raise_for_status()
        log.info("  Updated user '%s' (attributes synced)", username)
        return uid
    # Create
    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        headers=kc_headers(token), json=user, timeout=10,
    )
    r.raise_for_status()
    uid = r.headers.get("Location", "").rstrip("/").split("/")[-1]
    log.info("  Created user '%s' (enabled=%s)", username, user.get("enabled"))
    return uid


def kc_set_password(token: str, user_id: str, password: str = "Password1!") -> None:
    r = requests.put(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/reset-password",
        headers=kc_headers(token),
        json={"type": "password", "value": password, "temporary": False},
        timeout=10,
    )
    r.raise_for_status()


def kc_set_realm_attribute(token: str, attr_name: str, attr_value: str) -> None:
    # Fetch current realm
    r = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}",
        headers=kc_headers(token), timeout=10,
    )
    r.raise_for_status()
    realm = r.json()
    attrs = realm.get("attributes") or {}
    attrs[attr_name] = attr_value
    realm["attributes"] = attrs
    r2 = requests.put(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}",
        headers=kc_headers(token), json=realm, timeout=10,
    )
    r2.raise_for_status()
    log.info("  Realm attribute '%s' = '%s'", attr_name, attr_value)


# ── Ticketing helpers ─────────────────────────────────────────────────────────

def create_ticket(control_id: str, short_desc: str, description: str, priority: int) -> dict:
    r = requests.post(
        f"{TICKETING_URL}/api/now/table/incident",
        json={
            "short_description": short_desc,
            "description": description,
            "priority": priority,
            "category": "compliance",
            "caller_id": "meridian-seed",
            "control_id": control_id,
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["result"]


# ── Postgres helpers ──────────────────────────────────────────────────────────

def pg_insert_evidence(cur, ctrl_id: str, check_name: str, payload: dict, sig: str) -> str:
    cur.execute(
        """
        INSERT INTO evidence (control_id, check_name, collected_at, raw_data, signature)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
        """,
        (ctrl_id, check_name, payload["collected_at"], json.dumps(payload), sig),
    )
    return str(cur.fetchone()[0])


def pg_insert_run(cur, ctrl_id: str, status: str, ev_id: str,
                  summary: dict, run_at: datetime,
                  ticket_number: str | None = None,
                  ticket_sys_id: str | None = None) -> None:
    cur.execute(
        """
        INSERT INTO control_runs
            (control_id, run_at, status, evidence_id, summary, ticket_number, ticket_sys_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (ctrl_id, run_at, status, ev_id, json.dumps(summary), ticket_number, ticket_sys_id),
    )


def already_seeded(conn) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM control_runs WHERE control_id LIKE 'LA.%'"
        )
        return cur.fetchone()[0] > 0


# ── Seed Keycloak ─────────────────────────────────────────────────────────────

def seed_keycloak() -> None:
    log.info("=== Seeding Keycloak ===")
    token = kc_token()

    # ── Test users ────────────────────────────────────────────────────────────
    # Days since creation (for createdTimestamp offset) — Keycloak ignores
    # createdTimestamp on POST; it's set server-side. We just create the users
    # and set attributes. The agent's LA.01 check will find new users (≤30 days).

    users = [
        # Compliant users (have approvedBy)
        {
            "username": "user.alice",
            "enabled": True,
            "email": "alice@meridian.demo",
            "firstName": "Alice", "lastName": "Chen",
            "attributes": {"approvedBy": ["manager.jones"], "department": ["Engineering"]},
        },
        {
            "username": "user.bob",
            "enabled": True,
            "email": "bob@meridian.demo",
            "firstName": "Bob", "lastName": "Smith",
            "attributes": {"approvedBy": ["manager.patel"], "department": ["Sales"]},
        },
        # Non-compliant: missing approvedBy → LA.01 finding
        {
            "username": "user.charlie",
            "enabled": True,
            "email": "charlie@meridian.demo",
            "firstName": "Charlie", "lastName": "Nguyen",
            "attributes": {"department": ["Finance"]},   # no approvedBy
        },
        {
            "username": "user.diana",
            "enabled": True,
            "email": "diana@meridian.demo",
            "firstName": "Diana", "lastName": "Osei",
            "attributes": {},                            # no approvedBy
        },
        # Terminated users (disabled) with SLA tracking
        {
            "username": "user.frank",
            "enabled": False,
            "email": "frank@meridian.demo",
            "firstName": "Frank", "lastName": "Lopez",
            "attributes": {
                # Terminated 7 days ago → 6 days overdue against 1-day SLA
                "terminationRequestDate": [
                    (NOW - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                ],
                "department": ["Operations"],
            },
        },
        {
            "username": "user.grace",
            "enabled": False,
            "email": "grace@meridian.demo",
            "firstName": "Grace", "lastName": "Kim",
            "attributes": {
                # Terminated 4 days ago → 3 days overdue
                "terminationRequestDate": [
                    (NOW - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                ],
                "department": ["Engineering"],
            },
        },
        {
            "username": "user.henry",
            "enabled": False,
            "email": "henry@meridian.demo",
            "firstName": "Henry", "lastName": "Walsh",
            "attributes": {
                # Terminated today → 0 days overdue (within SLA)
                "terminationRequestDate": [
                    NOW.strftime("%Y-%m-%dT%H:%M:%S+00:00")
                ],
                "department": ["HR"],
            },
        },
    ]

    existing = {u["username"]: u["id"] for u in kc_list_users(token)}
    for u in users:
        uid = kc_upsert_user(token, u, existing)
        if uid and u["username"] not in existing:
            kc_set_password(token, uid)

    # ── Realm attribute: UAR date (95 days ago → overdue by 5 days) ───────────
    uar_date = (NOW - timedelta(days=95)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    kc_set_realm_attribute(token, "lastUarCompletedDate", uar_date)
    log.info("  UAR date set: %s (95 days ago → overdue)", uar_date)


# ── Seed Postgres ─────────────────────────────────────────────────────────────

def seed_postgres() -> None:
    log.info("=== Seeding Postgres ===")
    conn = psycopg2.connect(POSTGRES_DSN)
    conn.autocommit = False

    if already_seeded(conn):
        log.info("  Historical LA.* rows already present — skipping postgres seed")
        conn.close()
        return

    # Create tickets for the controls that are currently failing
    log.info("  Creating seed tickets in ticketing service …")
    t_la01 = create_ticket(
        "LA.01",
        "LA.01: 2 new account(s) provisioned without approval record",
        "user.charlie and user.diana were created without the required 'approvedBy' attribute.",
        2,   # High
    )
    t_la02 = create_ticket(
        "LA.02",
        "LA.02: 2 terminated account(s) breached the 1-day SLA (worst: 6d overdue)",
        "user.frank (6d overdue) and user.grace (3d overdue) still have active accounts "
        "beyond the 1-business-day termination SLA.",
        1,   # Critical
    )
    t_la03 = create_ticket(
        "LA.03",
        "LA.03: UAR overdue — last completed 95 days ago (SLA: every 90 days)",
        "The quarterly User Access Review has not been completed within the 90-day window. "
        "Last review: 95 days ago.",
        2,   # High
    )
    log.info("  Tickets: %s  %s  %s", t_la01["number"], t_la02["number"], t_la03["number"])

    with conn.cursor() as cur:
        _seed_la01(cur, t_la01)
        _seed_la02(cur, t_la02)
        _seed_la03(cur, t_la03)
        _seed_la04(cur)

    conn.commit()
    conn.close()
    log.info("  Postgres seed complete.")


def _ts(days_ago: float, hour: int = 9) -> datetime:
    """Return a UTC datetime N days ago at the given hour."""
    base = NOW.replace(hour=hour, minute=0, second=0, microsecond=0)
    return base - timedelta(days=days_ago)


def _make_evidence(ctrl_id: str, check: str, ts: datetime, status: str, summary: dict) -> tuple[dict, str]:
    payload = {
        "control_id":   ctrl_id,
        "check":        check,
        "collected_at": ts.isoformat(),
        "collector":    "meridian-agent",
        "realm":        REALM,
        "status":       status,
        "summary":      summary,
    }
    return payload, sign(payload)


# ── LA.01 — New Access ────────────────────────────────────────────────────────
# Pattern: PASS for first 27 days, FAIL for last 3 (when unapproved users appeared)

def _seed_la01(cur, ticket: dict) -> None:
    ctrl, check = "LA.01", "new_access_no_approval"
    ticket_number, ticket_sys_id = ticket["number"], ticket["sys_id"]
    fail_start_day = 3   # 3 days ago

    # Daily records: day -30 → day -4
    for day in range(30, fail_start_day, -1):
        ts = _ts(day)
        status = "pass"
        summary = {
            "lookback_days": 30, "required_attribute": "approvedBy",
            "recent_users_checked": 3, "missing_approval": 0,
        }
        ev, sig = _make_evidence(ctrl, check, ts, status, summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, status, ev_id, summary, ts)

    # Hourly records: last 3 days → FAIL (2 users without approval found)
    for h in range(fail_start_day * 24, 0, -1):
        ts = NOW - timedelta(hours=h)
        summary = {
            "lookback_days": 30, "required_attribute": "approvedBy",
            "recent_users_checked": 6, "missing_approval": 2,
        }
        tn = ticket_number if h == fail_start_day * 24 else ticket_number  # same ticket throughout
        ts_id = ticket_sys_id if h == fail_start_day * 24 else ticket_sys_id
        ev, sig = _make_evidence(ctrl, check, ts, "fail", summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, "fail", ev_id, summary, ts, tn, ts_id)

    log.info("  LA.01 seeded (%s)", ticket_number)


# ── LA.02 — Terminations SLA ──────────────────────────────────────────────────
# Pattern: PASS until day -6, then 1 breach (frank), then 2 breaches (frank + grace)

def _seed_la02(cur, ticket: dict) -> None:
    ctrl, check = "LA.02", "terminations_sla"
    ticket_number, ticket_sys_id = ticket["number"], ticket["sys_id"]

    # Phase 1: PASS — day -30 to day -7 (no SLA-tracked terminations yet)
    for day in range(30, 7, -1):
        ts = _ts(day)
        summary = {"sla_days": 1, "disabled_users_with_sla_tracking": 0, "sla_breaches": 0}
        ev, sig = _make_evidence(ctrl, check, ts, "pass", summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, "pass", ev_id, summary, ts)

    # Phase 2: FAIL — day -6 to day -4, frank's breach (7d - 1d SLA = 6d overdue at day-6)
    for day in range(7, 4, -1):
        ts = _ts(day)
        days_since_frank = 7 - day     # frank terminated 7 days ago; at point 'day' ago he was (7-day) days into breach
        frank_days_open = days_since_frank + day  # actual days from term date to this historical run
        # Simpler: frank's termination was 7 days ago from NOW, so at historical run (day days ago),
        # he had been terminated for (7 - day) days. That means at day=7 he was just terminated (0 days open).
        # SLA breach starts when days_open > 1. At day=6 days ago, frank had been terminated for 1 day (7-6=1),
        # so actually the breach starts at day=5 (7-5=2 days open > 1 day SLA).
        days_open_frank = 7 - day
        if days_open_frank <= 1:
            # Still within SLA
            status = "pass"
            summary = {"sla_days": 1, "disabled_users_with_sla_tracking": 1, "sla_breaches": 0}
        else:
            status = "fail"
            summary = {
                "sla_days": 1, "disabled_users_with_sla_tracking": 1, "sla_breaches": 1,
                "findings": [{"username": "user.frank", "days_overdue": days_open_frank - 1}],
            }
        ev, sig = _make_evidence(ctrl, check, ts, status, summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        tn = ticket_number if status == "fail" else None
        ts_id = ticket_sys_id if status == "fail" else None
        pg_insert_run(cur, ctrl, status, ev_id, summary, ts, tn, ts_id)

    # Phase 3: FAIL — last 4 days (hourly), frank + grace both breaching
    for h in range(4 * 24, 0, -1):
        ts = NOW - timedelta(hours=h)
        days_h = h / 24
        frank_days_open = 7 - days_h
        grace_days_open = 4 - days_h
        findings = []
        if frank_days_open > 1:
            findings.append({"username": "user.frank", "days_overdue": round(frank_days_open - 1, 1)})
        if grace_days_open > 1:
            findings.append({"username": "user.grace", "days_overdue": round(grace_days_open - 1, 1)})
        breaches = len(findings)
        summary = {
            "sla_days": 1,
            "disabled_users_with_sla_tracking": 3,
            "sla_breaches": breaches,
            "findings": findings,
        }
        status = "fail" if breaches > 0 else "pass"
        ev, sig = _make_evidence(ctrl, check, ts, status, summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, status, ev_id, summary, ts, ticket_number, ticket_sys_id)

    log.info("  LA.02 seeded (%s) — SLA breaches: frank (6d overdue), grace (3d overdue)", ticket_number)


# ── LA.03 — Quarterly UAR ─────────────────────────────────────────────────────
# UAR completed 95 days ago. Breach starts at day -5 (91 days old).

def _seed_la03(cur, ticket: dict) -> None:
    ctrl, check = "LA.03", "quarterly_uar"
    ticket_number, ticket_sys_id = ticket["number"], ticket["sys_id"]
    uar_date = (NOW - timedelta(days=95)).replace(microsecond=0)
    breach_day = 5   # 5 days ago (UAR was 90 days old = SLA limit; fail at 91+)

    # Daily records: day -30 to day -(breach_day+1)
    for day in range(30, breach_day, -1):
        ts = _ts(day)
        days_since_uar = 95 - day   # UAR age at this historical point
        status = "pass" if days_since_uar <= 90 else "fail"
        summary = {
            "max_days_since_uar": 90,
            "uar_attribute": "lastUarCompletedDate",
            "last_uar_date": uar_date.isoformat(),
            "days_since_uar": days_since_uar,
        }
        ev, sig = _make_evidence(ctrl, check, ts, status, summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, status, ev_id, summary, ts)

    # Hourly: last breach_day days → FAIL (UAR 91-95 days old)
    for h in range(breach_day * 24, 0, -1):
        ts = NOW - timedelta(hours=h)
        days_since_uar = 95 - (h / 24)
        status = "fail" if days_since_uar > 90 else "pass"
        summary = {
            "max_days_since_uar": 90,
            "uar_attribute": "lastUarCompletedDate",
            "last_uar_date": uar_date.isoformat(),
            "days_since_uar": round(days_since_uar, 1),
        }
        ev, sig = _make_evidence(ctrl, check, ts, status, summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        tn = ticket_number if status == "fail" else None
        ts_id = ticket_sys_id if status == "fail" else None
        pg_insert_run(cur, ctrl, status, ev_id, summary, ts, tn, ts_id)

    log.info("  LA.03 seeded (%s) — UAR 95 days ago, breach at day -5", ticket_number)


# ── LA.04 — Admin Access ──────────────────────────────────────────────────────
# Consistently passing: 1 admin ≤ max of 3. No ticket.

def _seed_la04(cur) -> None:
    ctrl, check = "LA.04", "admin_access_count"

    for day in range(30, 0, -1):
        ts = _ts(day)
        summary = {"role_name": "admin", "admin_count": 1, "max_allowed": 3}
        ev, sig = _make_evidence(ctrl, check, ts, "pass", summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, "pass", ev_id, summary, ts)

    # Hourly for last 24h
    for h in range(24, 0, -1):
        ts = NOW - timedelta(hours=h)
        summary = {"role_name": "admin", "admin_count": 1, "max_allowed": 3}
        ev, sig = _make_evidence(ctrl, check, ts, "pass", summary)
        ev_id = pg_insert_evidence(cur, ctrl, check, ev, sig)
        pg_insert_run(cur, ctrl, "pass", ev_id, summary, ts)

    log.info("  LA.04 seeded — 1 admin / max 3, consistently PASS")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    seed_keycloak()
    seed_postgres()
    log.info("=== Seed complete ===")

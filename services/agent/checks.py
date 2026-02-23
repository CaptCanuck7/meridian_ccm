"""
Control check implementations.

Each function receives a KeycloakClient, a params dict from controls.yaml,
and returns a CheckResult.

REGISTRY maps the check name (from controls.yaml) to the function.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from keycloak_client import KeycloakClient

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    status: str                            # "pass" | "fail" | "error"
    summary: dict[str, Any]               # metrics stored as evidence
    findings: list[dict[str, Any]] = field(default_factory=list)
    short_description: str = ""           # ticket subject (fail only)
    description: str = ""                 # ticket body   (fail only)


# ── Check implementations ──────────────────────────────────────────────────────

def new_access_no_approval(kc: KeycloakClient, params: dict, **_) -> CheckResult:
    """LA.01 — New access grants must have an approvedBy attribute on record."""
    lookback_days: int = params.get("lookback_days", 30)
    required_attr: str = params.get("required_attribute", "approvedBy")

    cutoff_ms = int(
        (datetime.now(timezone.utc) - timedelta(days=lookback_days)).timestamp() * 1000
    )

    try:
        users = kc.list_users()
    except Exception as exc:
        log.error("new_access_no_approval: failed to list users: %s", exc)
        return CheckResult("error", {"error": str(exc)})

    recent = [
        u for u in users
        if u.get("enabled", True) and u.get("createdTimestamp", 0) >= cutoff_ms
    ]

    non_compliant: list[dict] = []
    for user in recent:
        attrs = user.get("attributes") or {}
        if not attrs.get(required_attr):
            created_dt = datetime.fromtimestamp(
                user["createdTimestamp"] / 1000, tz=timezone.utc
            )
            non_compliant.append({
                "username": user.get("username"),
                "user_id": user["id"],
                "created": created_dt.isoformat(),
            })

    count = len(non_compliant)
    summary = {
        "lookback_days": lookback_days,
        "required_attribute": required_attr,
        "recent_users_checked": len(recent),
        "missing_approval": count,
    }

    if count > 0:
        names = ", ".join(u["username"] for u in non_compliant)
        return CheckResult(
            "fail",
            summary,
            findings=non_compliant,
            short_description=f"LA.01: {count} new account(s) provisioned without approval record",
            description=(
                f"{count} account(s) created in the last {lookback_days} days "
                f"lack the '{required_attr}' attribute.\nAffected: {names}"
            ),
        )
    return CheckResult("pass", summary)


def terminations_sla(kc: KeycloakClient, params: dict, **_) -> CheckResult:
    """LA.02 — Terminated accounts must be disabled within the SLA window."""
    sla_days: int = params.get("sla_days", 1)
    term_attr: str = params.get("termination_attribute", "terminationRequestDate")

    try:
        users = kc.list_users()
    except Exception as exc:
        log.error("terminations_sla: failed to list users: %s", exc)
        return CheckResult("error", {"error": str(exc)})

    disabled = [u for u in users if not u.get("enabled", True)]

    breaches: list[dict] = []
    tracked = 0
    now = datetime.now(timezone.utc)

    for user in disabled:
        attrs = user.get("attributes") or {}
        raw_dates = attrs.get(term_attr, [])
        if not raw_dates:
            continue  # no SLA tracking attribute — skip

        tracked += 1
        raw = raw_dates[0] if isinstance(raw_dates, list) else raw_dates
        try:
            term_date = datetime.fromisoformat(raw)
            if term_date.tzinfo is None:
                term_date = term_date.replace(tzinfo=timezone.utc)
        except ValueError:
            log.warning("terminations_sla: bad date '%s' for user %s", raw, user.get("username"))
            continue

        days_open = (now - term_date).days
        if days_open > sla_days:
            breaches.append({
                "username": user.get("username"),
                "user_id": user["id"],
                "termination_requested": term_date.isoformat(),
                "days_open": days_open,
                "days_overdue": days_open - sla_days,
            })

    count = len(breaches)
    summary = {
        "sla_days": sla_days,
        "disabled_users_with_sla_tracking": tracked,
        "sla_breaches": count,
    }

    if count > 0:
        names = ", ".join(b["username"] for b in breaches)
        worst = max(b["days_overdue"] for b in breaches)
        return CheckResult(
            "fail",
            summary,
            findings=breaches,
            short_description=(
                f"LA.02: {count} terminated account(s) breached the {sla_days}-day SLA "
                f"(worst: {worst}d overdue)"
            ),
            description=(
                f"{count} account(s) were not disabled within the {sla_days}-day SLA "
                f"after termination request.\nAffected: {names}"
            ),
        )
    return CheckResult("pass", summary)


def quarterly_uar(kc: KeycloakClient, params: dict, **_) -> CheckResult:
    """LA.03 — Quarterly User Access Review must be completed within max_days_since_uar."""
    max_days: int = params.get("max_days_since_uar", 90)
    uar_attr: str = params.get("uar_attribute", "lastUarCompletedDate")

    try:
        realm = kc.get_realm()
    except Exception as exc:
        log.error("quarterly_uar: failed to read realm: %s", exc)
        return CheckResult("error", {"error": str(exc)})

    realm_attrs = realm.get("attributes") or {}
    uar_val = realm_attrs.get(uar_attr)

    base_summary = {"max_days_since_uar": max_days, "uar_attribute": uar_attr}

    if not uar_val:
        return CheckResult(
            "fail",
            {**base_summary, "last_uar_date": None, "days_since_uar": None},
            short_description="LA.03: No UAR completion date recorded — review overdue",
            description=(
                "No User Access Review completion date found in the realm attributes. "
                "A UAR must be completed and the date recorded."
            ),
        )

    try:
        uar_date = datetime.fromisoformat(uar_val)
        if uar_date.tzinfo is None:
            uar_date = uar_date.replace(tzinfo=timezone.utc)
    except ValueError:
        return CheckResult("error", {"error": f"Invalid {uar_attr} value: '{uar_val}'"})

    days_since = (datetime.now(timezone.utc) - uar_date).days
    summary = {**base_summary, "last_uar_date": uar_val, "days_since_uar": days_since}

    if days_since > max_days:
        return CheckResult(
            "fail",
            summary,
            short_description=(
                f"LA.03: UAR overdue — last completed {days_since} days ago "
                f"(SLA: every {max_days} days)"
            ),
            description=(
                f"The last User Access Review was completed {days_since} days ago "
                f"({uar_val}). The required cadence is every {max_days} days."
            ),
        )
    return CheckResult("pass", summary)


def admin_access_count(kc: KeycloakClient, params: dict, **_) -> CheckResult:
    """LA.04 — Privileged role member count must not exceed the approved threshold."""
    role_name: str = params.get("role_name", "admin")
    max_admins: int = params.get("max_admins", 3)

    try:
        admins = kc.get_role_users(role_name)
    except Exception as exc:
        log.error("admin_access_count: could not fetch users for role '%s': %s", role_name, exc)
        return CheckResult("error", {"error": str(exc), "role_name": role_name})

    count = len(admins)
    summary = {"role_name": role_name, "admin_count": count, "max_allowed": max_admins}

    if count > max_admins:
        return CheckResult(
            "fail",
            summary,
            findings=[{"username": u.get("username"), "user_id": u["id"]} for u in admins],
            short_description=(
                f"LA.04: Admin account count ({count}) exceeds threshold ({max_admins})"
            ),
            description=(
                f"The realm has {count} users with the '{role_name}' role, "
                f"exceeding the approved maximum of {max_admins}."
            ),
        )
    return CheckResult("pass", summary)


# ── Registry ───────────────────────────────────────────────────────────────────

REGISTRY: dict[str, Any] = {
    "new_access_no_approval": new_access_no_approval,
    "terminations_sla":       terminations_sla,
    "quarterly_uar":          quarterly_uar,
    "admin_access_count":     admin_access_count,
}

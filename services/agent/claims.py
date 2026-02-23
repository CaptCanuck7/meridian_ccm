"""
OTVP Claims layer.

A Claim sits between a raw CheckResult and a TrustEnvelope. It represents
the agent's verifiable assertion about a control domain, including a
plain-English opinion, confidence score, caveats, and recommendations.

Every Claim is signed with the agent's Ed25519 private key.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from checks import CheckResult
    from crypto.keys import KeyPair


AGENT_ID      = "meridian-agent"
AGENT_VERSION = "2.0.0"

# TTL for claims: 24 hours (one agent run cycle covers at most this window)
DEFAULT_TTL_SECONDS = 86_400


class ClaimResult(str, Enum):
    SATISFIED      = "SATISFIED"
    NOT_SATISFIED  = "NOT_SATISFIED"
    PARTIAL        = "PARTIAL"
    INDETERMINATE  = "INDETERMINATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ── Control → domain mapping ──────────────────────────────────────────────────

CONTROL_DOMAINS: dict[str, str] = {
    "LA.01": "identity_and_access.logical_access.new_access",
    "LA.02": "identity_and_access.logical_access.terminations",
    "LA.03": "identity_and_access.logical_access.user_access_review",
    "LA.04": "identity_and_access.logical_access.admin_access",
}


# ── Confidence calculation ────────────────────────────────────────────────────

def _compute_confidence(result: "CheckResult", ctrl_id: str) -> float:
    """
    Derive a 0.0–1.0 confidence score from the check result.

    - error  → 0.1 (something failed; we cannot be confident)
    - pass   → 1.0 (fully satisfied)
    - fail   → computed from the fraction that actually passed

    For binary controls (LA.03, LA.04) a fail maps directly to 0.0.
    For population controls (LA.01, LA.02) we compute 1 - failure_rate
    so partial compliance is reflected.
    """
    if result.status == "error":
        return 0.1
    if result.status == "pass":
        return 1.0

    # status == "fail"
    summary = result.summary or {}

    if ctrl_id == "LA.01":
        checked = summary.get("recent_users_checked", 0)
        missing = summary.get("missing_approval", 0)
        if checked > 0:
            return round(1.0 - (missing / checked), 4)
        return 0.0

    if ctrl_id == "LA.02":
        tracked = summary.get("disabled_users_with_sla_tracking", 0)
        breaches = summary.get("sla_breaches", 0)
        if tracked > 0:
            return round(1.0 - (breaches / tracked), 4)
        return 0.0

    # LA.03, LA.04 — binary
    return 0.0


def _map_result(result: "CheckResult") -> ClaimResult:
    """Map a CheckResult status to a ClaimResult enum value."""
    return {
        "pass":  ClaimResult.SATISFIED,
        "fail":  ClaimResult.NOT_SATISFIED,
        "error": ClaimResult.INDETERMINATE,
    }.get(result.status, ClaimResult.INDETERMINATE)


def _build_opinion(result: "CheckResult", ctrl_id: str, ctrl_name: str) -> str:
    """Generate a plain-English opinion from the check result."""
    if result.status == "pass":
        return f"All checks for {ctrl_id} ({ctrl_name}) passed. No issues found."
    if result.status == "error":
        err = (result.summary or {}).get("error", "unknown error")
        return f"The agent encountered an error evaluating {ctrl_id}: {err}. Results are inconclusive."

    # fail — build from summary metrics
    summary = result.summary or {}

    if ctrl_id == "LA.01":
        checked = summary.get("recent_users_checked", 0)
        missing = summary.get("missing_approval", 0)
        return (
            f"Of {checked} account(s) provisioned in the last "
            f"{summary.get('lookback_days', '?')} days, {missing} lack the "
            f"'{summary.get('required_attribute', 'approvedBy')}' approval attribute. "
            f"This indicates accounts provisioned outside the approved workflow."
        )

    if ctrl_id == "LA.02":
        breaches = summary.get("sla_breaches", 0)
        tracked  = summary.get("disabled_users_with_sla_tracking", 0)
        sla      = summary.get("sla_days", 1)
        return (
            f"{breaches} of {tracked} terminated account(s) were not disabled within "
            f"the {sla}-day SLA. Delayed revocation leaves residual access active."
        )

    if ctrl_id == "LA.03":
        days    = summary.get("days_since_uar")
        max_days = summary.get("max_days_since_uar", 90)
        if days is None:
            return "No User Access Review completion date is recorded. The UAR is overdue."
        return (
            f"The last User Access Review was completed {days} days ago, "
            f"exceeding the required cadence of every {max_days} days."
        )

    if ctrl_id == "LA.04":
        count   = summary.get("admin_count", 0)
        allowed = summary.get("max_allowed", 3)
        role    = summary.get("role_name", "admin")
        return (
            f"There are {count} users with the '{role}' role, exceeding the "
            f"approved maximum of {allowed}. Excess privileged accounts expand blast radius."
        )

    return result.short_description or f"{ctrl_id} control check failed."


def _build_caveats(result: "CheckResult", ctrl_id: str) -> list[str]:
    """Generate caveat strings from the check result findings."""
    caveats: list[str] = []
    if result.status == "error":
        caveats.append("Check failed with an error; evidence may be incomplete.")
        return caveats

    summary = result.summary or {}

    if ctrl_id == "LA.01" and result.status == "fail":
        missing = summary.get("missing_approval", 0)
        caveats.append(
            f"{missing} account(s) are missing the required approval attribute and "
            "may represent unauthorised access grants."
        )

    if ctrl_id == "LA.02" and result.status == "fail":
        for f in result.findings:
            overdue = f.get("days_overdue", 0)
            uname   = f.get("username", "?")
            caveats.append(f"User '{uname}' is {overdue} day(s) overdue for access revocation.")

    if ctrl_id == "LA.03" and result.status == "fail":
        days = summary.get("days_since_uar")
        if days is None:
            caveats.append("No UAR completion date found in the realm configuration.")
        else:
            caveats.append(f"Access review is {days - summary.get('max_days_since_uar', 90)} day(s) overdue.")

    if ctrl_id == "LA.04" and result.status == "fail":
        excess = summary.get("admin_count", 0) - summary.get("max_allowed", 0)
        caveats.append(f"{excess} excess privileged account(s) require immediate review and removal.")

    return caveats


def _build_recommendations(result: "CheckResult", ctrl_id: str) -> list[str]:
    """Generate remediation recommendations."""
    if result.status in ("pass", "error"):
        return []

    recs: dict[str, list[str]] = {
        "LA.01": [
            "Audit provisioning workflow to enforce approval gates before account creation.",
            "Set the required 'approvedBy' attribute for all flagged accounts retroactively.",
            "Enable automated provisioning enforcement that blocks account creation without an approved request.",
        ],
        "LA.02": [
            "Immediately disable access for all accounts past the SLA deadline.",
            "Implement automated deprovisioning triggered by termination events.",
            "Review and tighten the offboarding SLA with HR and IT operations.",
        ],
        "LA.03": [
            "Complete a User Access Review immediately and record the date in realm attributes.",
            "Schedule quarterly UAR reminders and assign a named owner.",
            "Automate UAR initiation and tracking within the IAM platform.",
        ],
        "LA.04": [
            "Immediately remove or downgrade excess privileged accounts.",
            "Implement a Just-in-Time (JIT) privileged access model.",
            "Establish a periodic admin account review cadence.",
        ],
    }
    return recs.get(ctrl_id, ["Review and remediate the identified control failure."])


# ── Main builder ─────────────────────────────────────────────────────────────

@dataclass
class Claim:
    claim_id:        str
    domain:          str
    assertion:       str
    result:          ClaimResult
    confidence:      float
    evidence_refs:   list[str]          # evidence UUIDs from the Merkle store
    opinion:         str
    caveats:         list[str]
    recommendations: list[str]
    scope:           dict[str, Any]     # environment, products, systems
    valid_from:      str                # ISO-8601 UTC
    ttl_seconds:     int
    agent_id:        str
    agent_version:   str
    signature:       str = ""           # set after construction

    def signable_dict(self) -> dict:
        """Return all fields except signature (used as signing payload)."""
        return {
            "claim_id":        self.claim_id,
            "domain":          self.domain,
            "assertion":       self.assertion,
            "result":          self.result.value if isinstance(self.result, ClaimResult) else self.result,
            "confidence":      self.confidence,
            "evidence_refs":   self.evidence_refs,
            "opinion":         self.opinion,
            "caveats":         self.caveats,
            "recommendations": self.recommendations,
            "scope":           self.scope,
            "valid_from":      self.valid_from,
            "ttl_seconds":     self.ttl_seconds,
            "agent_id":        self.agent_id,
            "agent_version":   self.agent_version,
        }

    def to_dict(self) -> dict:
        d = self.signable_dict()
        d["signature"] = self.signature
        return d


def build_claim(
    result: "CheckResult",
    evidence_id: str,
    ctrl: dict,
    key_pair: "KeyPair",
    product_ids: list[str],
) -> Claim:
    """
    Build and sign a Claim from a CheckResult.

    Args:
        result:      The output of a control check function.
        evidence_id: UUID of the evidence row in the DB (Merkle store ref).
        ctrl:        Control metadata dict from controls.yaml.
        key_pair:    Agent's Ed25519 keypair for signing.
        product_ids: List of product IDs this control applies to.
    """
    ctrl_id   = ctrl["id"]
    ctrl_name = ctrl["name"]
    now       = datetime.now(timezone.utc).isoformat()

    # Derive claim result (PARTIAL if pass rate is between 0 and 1)
    confidence = _compute_confidence(result, ctrl_id)
    if result.status == "pass":
        claim_result = ClaimResult.SATISFIED
    elif result.status == "error":
        claim_result = ClaimResult.INDETERMINATE
    elif 0.0 < confidence < 1.0:
        claim_result = ClaimResult.PARTIAL
    else:
        claim_result = ClaimResult.NOT_SATISFIED

    claim = Claim(
        claim_id        = str(uuid.uuid4()),
        domain          = CONTROL_DOMAINS.get(ctrl_id, f"identity_and_access.logical_access.{ctrl_id.lower().replace('.', '_')}"),
        assertion       = ctrl.get("description", ctrl_name).strip(),
        result          = claim_result,
        confidence      = confidence,
        evidence_refs   = [evidence_id],
        opinion         = _build_opinion(result, ctrl_id, ctrl_name),
        caveats         = _build_caveats(result, ctrl_id),
        recommendations = _build_recommendations(result, ctrl_id),
        scope           = {
            "environment": "production",
            "products":    product_ids,
            "systems":     ["keycloak"],
            "realm":       "master",
        },
        valid_from      = now,
        ttl_seconds     = DEFAULT_TTL_SECONDS,
        agent_id        = AGENT_ID,
        agent_version   = AGENT_VERSION,
    )

    # Sign the claim
    claim.signature = key_pair.sign(claim.signable_dict())
    return claim

"""
OTVP TrustEnvelope — wraps Claims with cryptographic provenance.

A TrustEnvelope is the top-level output of the agent for one
control × product combination. It:
  - Wraps one or more signed Claims
  - References an EvidenceSummary (total items, Merkle root, window)
  - Computes a composite TrustLevel from Claim confidence scores
  - Computes per-domain scores
  - Is itself signed with the agent's Ed25519 private key

TrustLevel thresholds (composite confidence):
  VERIFIED  ≥ 0.95
  HIGH      ≥ 0.75
  MEDIUM    ≥ 0.55
  LOW       ≥ 0.30
  CRITICAL  <  0.30
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from claims import Claim
    from crypto.keys import KeyPair
    from crypto.merkle import MerkleTree

from claims import AGENT_ID, AGENT_VERSION, ClaimResult


# ── Enums ─────────────────────────────────────────────────────────────────────

class TrustLevel(str, Enum):
    VERIFIED = "VERIFIED"   # ≥ 95 %
    HIGH     = "HIGH"       # ≥ 75 %
    MEDIUM   = "MEDIUM"     # ≥ 55 %
    LOW      = "LOW"        # ≥ 30 %
    CRITICAL = "CRITICAL"   # <  30 %


class DisclosureLevel(str, Enum):
    FULL            = "FULL"
    CLAIMS_ONLY     = "CLAIMS_ONLY"
    ZERO_KNOWLEDGE  = "ZERO_KNOWLEDGE"


# ── Helpers ───────────────────────────────────────────────────────────────────

def compute_trust_level(composite_confidence: float) -> TrustLevel:
    if composite_confidence >= 0.95:
        return TrustLevel.VERIFIED
    if composite_confidence >= 0.75:
        return TrustLevel.HIGH
    if composite_confidence >= 0.55:
        return TrustLevel.MEDIUM
    if composite_confidence >= 0.30:
        return TrustLevel.LOW
    return TrustLevel.CRITICAL


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class EvidenceSummary:
    total_items:              int
    merkle_root:              str | None
    collection_window_start:  str
    collection_window_end:    str
    domains_covered:          list[str]

    def to_dict(self) -> dict:
        return {
            "total_items":             self.total_items,
            "merkle_root":             self.merkle_root,
            "collection_window_start": self.collection_window_start,
            "collection_window_end":   self.collection_window_end,
            "domains_covered":         self.domains_covered,
        }


@dataclass
class TrustEnvelope:
    envelope_id:          str
    control_id:           str
    control_name:         str
    product_id:           str
    claims:               list[dict]      # serialised signed Claim dicts
    evidence_summary:     EvidenceSummary
    trust_level:          TrustLevel
    composite_confidence: float
    domain_scores:        dict[str, Any]  # {domain: {satisfied, total, avg_confidence}}
    disclosure_level:     DisclosureLevel
    valid_from:           str
    valid_until:          str
    agent_id:             str
    agent_version:        str
    public_key:           str             # Ed25519 public key hex
    framework_mappings:   dict[str, list[str]]
    signature:            str = ""        # set after construction

    def signable_dict(self) -> dict:
        return {
            "envelope_id":          self.envelope_id,
            "control_id":           self.control_id,
            "control_name":         self.control_name,
            "product_id":           self.product_id,
            "claims":               self.claims,
            "evidence_summary":     self.evidence_summary.to_dict(),
            "trust_level":          self.trust_level.value if isinstance(self.trust_level, TrustLevel) else self.trust_level,
            "composite_confidence": self.composite_confidence,
            "domain_scores":        self.domain_scores,
            "disclosure_level":     self.disclosure_level.value if isinstance(self.disclosure_level, DisclosureLevel) else self.disclosure_level,
            "valid_from":           self.valid_from,
            "valid_until":          self.valid_until,
            "agent_id":             self.agent_id,
            "agent_version":        self.agent_version,
            "public_key":           self.public_key,
            "framework_mappings":   self.framework_mappings,
        }

    def to_dict(self) -> dict:
        d = self.signable_dict()
        d["signature"] = self.signature
        return d


# ── Domain score computation ──────────────────────────────────────────────────

def _compute_domain_scores(claims: list["Claim"]) -> dict[str, Any]:
    """
    Per-domain aggregate: how many claims satisfied, total, and avg confidence.
    """
    domains: dict[str, dict] = {}
    for claim in claims:
        d = claim.domain
        if d not in domains:
            domains[d] = {"satisfied": 0, "total": 0, "confidence_sum": 0.0}
        domains[d]["total"] += 1
        domains[d]["confidence_sum"] += claim.confidence
        if claim.result == ClaimResult.SATISFIED:
            domains[d]["satisfied"] += 1

    return {
        domain: {
            "satisfied":      v["satisfied"],
            "total":          v["total"],
            "avg_confidence": round(v["confidence_sum"] / v["total"], 4) if v["total"] else 0.0,
        }
        for domain, v in domains.items()
    }


# ── Builder ───────────────────────────────────────────────────────────────────

def build_trust_envelope(
    ctrl: dict,
    product_id: str,
    claims: list["Claim"],
    merkle_tree: "MerkleTree",
    key_pair: "KeyPair",
    collection_window_start: str,
    disclosure_level: DisclosureLevel = DisclosureLevel.FULL,
) -> TrustEnvelope:
    """
    Construct and sign a TrustEnvelope for one control × product combination.

    Args:
        ctrl:                    Control metadata dict from controls.yaml.
        product_id:              Product identifier (e.g. "P1").
        claims:                  Signed Claims for this control.
        merkle_tree:             The global evidence Merkle tree (current state).
        key_pair:                Agent Ed25519 keypair.
        collection_window_start: ISO-8601 start of this run cycle.
        disclosure_level:        How much information to include.
    """
    now          = datetime.now(timezone.utc)
    valid_from   = now.isoformat()
    valid_until  = (now + timedelta(seconds=86_400)).isoformat()

    # Composite confidence = mean of all claim confidences
    composite_confidence = (
        round(sum(c.confidence for c in claims) / len(claims), 4)
        if claims else 0.0
    )
    trust_level  = compute_trust_level(composite_confidence)
    domain_scores = _compute_domain_scores(claims)

    # Evidence summary using current Merkle tree state
    evidence_summary = EvidenceSummary(
        total_items             = merkle_tree.count,
        merkle_root             = merkle_tree.root,
        collection_window_start = collection_window_start,
        collection_window_end   = valid_from,
        domains_covered         = list(domain_scores.keys()),
    )

    envelope = TrustEnvelope(
        envelope_id          = str(uuid.uuid4()),
        control_id           = ctrl["id"],
        control_name         = ctrl["name"],
        product_id           = product_id,
        claims               = [c.to_dict() for c in claims],
        evidence_summary     = evidence_summary,
        trust_level          = trust_level,
        composite_confidence = composite_confidence,
        domain_scores        = domain_scores,
        disclosure_level     = disclosure_level,
        valid_from           = valid_from,
        valid_until          = valid_until,
        agent_id             = AGENT_ID,
        agent_version        = AGENT_VERSION,
        public_key           = key_pair.public_key_hex,
        framework_mappings   = ctrl.get("framework_mappings", {}),
    )

    envelope.signature = key_pair.sign(envelope.signable_dict())
    return envelope

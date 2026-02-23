# Meridian — Upgrade Instructions

## Context
Meridian is a continuous control monitoring platform based on the OTVP (Open Trust
Verification Protocol) specification. It runs on Docker Compose (Windows) and monitors
IAM/Logical Access controls across multiple products using Keycloak (simulating Saviynt)
and a mock FastAPI ticketing service (simulating ServiceNow). Evidence is stored in
PostgreSQL and surfaced via a Streamlit dashboard.

Current controls: LA.01 (New Access), LA.02 (Terminations with SLA tracking),
LA.03 (Quarterly UAR), LA.04 (Admin Access).
Products: P1 covers LA.01–LA.03. P2 covers LA.01–LA.04.

## Terminology
- Use "Deviations" not "Exceptions" everywhere — in code, variables, UI, database fields,
  and comments. This is internal terminology and must be consistent throughout.

---

## Two Upgrades Required

Work in stages. Complete and verify Stage 1 before starting Stage 2.

---

## Stage 1: Cryptographic Foundation Upgrade

Replace the current HMAC-SHA256 signing with a proper OTVP-compliant cryptographic stack.

### 1a. Ed25519 Signing
- Replace signer.py with Ed25519 asymmetric signing using the `cryptography` Python library
- Generate a KeyPair (private + public key) on agent startup, persist to disk
- All signing uses the private key; verification uses only the public key
- Canonical JSON signing: sort_keys=True, no extra whitespace, UTF-8 encoded

### 1b. Merkle Tree Evidence Store
- Implement an append-only Merkle tree that chains every evidence item
- Each leaf = SHA-256 hash of the serialized evidence item
- Store the Merkle root in every TrustEnvelope's evidence_summary
- Merkle proofs must be verifiable independently (proof_hashes + root_hash)
- Replace or wrap the current evidence storage so every item is chained

### 1c. Claims Layer
Introduce a Claims layer between control check results and TrustEnvelopes.
Each Claim must have:
- claim_id (uuid)
- domain (e.g. "identity_and_access.logical_access.terminations")
- assertion (plain English, e.g. "All terminated users had access revoked within SLA")
- result: SATISFIED / NOT_SATISFIED / PARTIAL / INDETERMINATE / NOT_APPLICABLE
- confidence: float 0.0–1.0
- evidence_refs: list of evidence_ids from the Merkle store
- opinion: assessment text (plain English summary of what the agent found)
- caveats: list of strings (notable exceptions or limitations)
- recommendations: list of strings (what should be done to remediate)
- scope: environment, products, systems covered
- valid_from + ttl_seconds
- agent_id, agent_version
- Ed25519 signature (signs all fields above)

### 1d. TrustEnvelope Upgrade
Update TrustEnvelope to:
- Wrap Claims (not raw check results)
- Include evidence_summary with: total_items, merkle_root, collection_window_start/end, domains_covered
- Compute composite trust level from claim confidence scores:
  - VERIFIED: 95%+
  - HIGH: 75–94%
  - MEDIUM: 55–74%
  - LOW: 30–54%
  - CRITICAL: below 30%
- Compute per-domain scores (claims_satisfied / claims_total, avg confidence)
- Support disclosure_level: FULL / CLAIMS_ONLY / ZERO_KNOWLEDGE
- Include valid_until TTL timestamp
- Ed25519 signature on the full envelope

### 1e. Framework Mappings
Add SOC 2, ISO 27001, HIPAA, and NIST CSF mappings to the control registry.
Example for LA.02 (Terminations):
- SOC 2: CC6.2, CC6.5
- ISO 27001: A.9.2.6
- NIST CSF: PR.AC-1
- HIPAA: §164.312(a)(1)

Map all four controls (LA.01–LA.04) appropriately.

### Reference Implementation
The OTVP Agent SDK at https://github.com/wharmer68/otvp-agent-sdk implements
this cryptographic approach. Use it as a reference for:
- crypto/keys.py — Ed25519 KeyPair implementation
- crypto/merkle.py — Merkle tree implementation
- claims.py — Claim dataclass and ClaimResult enum
- envelope.py — TrustEnvelope with TrustLevel scoring

### Stage 1 Verification
Before proceeding to Stage 2, confirm:
- All existing control checks still run and produce results
- Ed25519 signatures verify correctly on evidence, claims, and envelopes
- Merkle proofs verify for all evidence items
- TrustEnvelopes include composite trust level and Merkle root
- No references to HMAC-SHA256 remain in signing paths
- All existing tests pass

---

## Stage 2: Dashboard Redesign

Replace the current Streamlit dashboard with a redesigned version.

### Visual Design
- Dark background: #0d1117 or similar dark navy/black
- Primary accent: teal/green (#00d4aa or similar)
- Secondary accents: orange for PARTIAL/warnings, red for CRITICAL/failures
- Monospaced uppercase labels for section headers (e.g. "TRUST ENVELOPE", "FINDINGS")
- Clean card-based layout with subtle borders
- No excessive padding or wasted space

### Top KPI Row (6 cards)
1. Total Envelopes
2. Total Evidence Items
3. Claims Evaluated
4. Satisfied
5. Deviations (open, not resolved)
6. Open Tickets

### Collapsible Explainer Panel
Add a collapsible "HOW TO READ THIS DASHBOARD" section explaining:
- What a Trust Envelope is (replaces audit report finding)
- Confidence % — what 100% means vs 67% (scanned population, not a sample)
- Trust Levels — VERIFIED/HIGH/MEDIUM/LOW/CRITICAL with thresholds
- Claim Results — SATISFIED / PARTIAL / NOT SATISFIED / N/A
- Framework Badges — what CC6.1 etc. mean
- Cryptographic Verification — Ed25519 + Merkle root explanation
- What makes this different from a traditional SOC 2 report

### Trust Envelope Cards (main content)
Each TrustEnvelope renders as a card showing:
- Section label: "TRUST ENVELOPE" + framework badge(s) (e.g. CC6.2, CC6.5)
- Control title (large, e.g. "LA.02 — Terminations")
- Product badge (P1 / P2) + envelope ID + timestamp (smaller, muted)
- Top-right: circular confidence gauge + trust level badge (color-coded)
- Description of what this control checks
- Framework mapping rows (e.g. "CC6.2 — User deprovisioning...")
- Mini KPI row: Evidence | Claims | Satisfied | Partial | Failed
- FINDINGS section: bullet list of plain-English findings from claim opinions
- Confidence explanation bar
- Recommendations (if any) in a highlighted block
- Merkle root hash display
- Expandable CLAIMS section showing each claim with result badge,
  confidence, assertion text, domain path, caveats, and recommendations

### Trust Level Badge Colors
- VERIFIED: teal/green
- HIGH: green
- MEDIUM: yellow/amber
- LOW: orange
- CRITICAL: red

### Sidebar Navigation
Pages:
1. Overview — all envelope cards
2. By Product — grouped by P1 / P2
3. Deviations — deviation cards (see below)
4. Evidence — filterable evidence table with signatures

Filters (apply contextually per page):
- Product (P1, P2, All)
- Control (LA.01, LA.02, LA.03, LA.04, All)
- Trust Level (VERIFIED, HIGH, MEDIUM, LOW, CRITICAL, All)
- Date range

### Deviations Page
Show a deviation card per open failing control/product combination:
- Control name + product badge
- What failed (from claim assertion + caveats)
- How long it has been open (calculated from first failure timestamp)
- Linked ticket number (from ticketing service)
- Recommended action (from claim recommendations field)
- Current trust level badge

### Evidence Page
- Filterable table: product, control, date range
- Columns: evidence_id, control, product, collected_at, domain, status, signature (truncated)
- Expandable row showing full evidence JSON
- Merkle proof verification status per item

### Stage 2 Verification
- Dashboard loads without errors at http://localhost:8501
- All four controls visible with correct product scoping
- Deviations page shows open items with ticket links
- Filters work correctly on all pages
- No remaining references to "Exceptions" anywhere in the codebase

# Meridian CCM

Continuous Control Monitoring platform built on the [OTVP](https://github.com/wharmer68/otvp-agent-sdk) (Open Trust Verification Protocol) specification. Meridian continuously evaluates IAM / Logical Access controls across multiple products and surfaces cryptographically-verified findings in a real-time dashboard.

## What it does

An agent polls Keycloak (simulating Saviynt) every 60 seconds, runs four Logical Access controls, and writes cryptographically-signed evidence into PostgreSQL. Each run produces:

- **Evidence items** — raw check results, SHA-256 Merkle-chained and Ed25519-signed
- **Claims** — plain-English assertions with confidence scores (SATISFIED / PARTIAL / NOT_SATISFIED)
- **Trust Envelopes** — machine-generated audit findings, one per control × product, with a composite trust level and Merkle root

A Streamlit dashboard reads the envelopes and displays live compliance posture.

## Controls

| ID | Name | Severity | Products |
|----|------|----------|----------|
| LA.01 | New Access — Approval Required | High | P1, P2 |
| LA.02 | Terminations — SLA Compliance | Critical | P1, P2 |
| LA.03 | Quarterly User Access Review (UAR) | High | P1, P2 |
| LA.04 | Admin Access — Count and Review | Critical | P2 |

Framework mappings: SOC 2 (CC6.x) and ISO 27001 (A.9.x) for all controls.

## Architecture

```
┌─────────────┐     polls      ┌───────────┐
│  Keycloak   │◄───────────────│           │
│  (Saviynt)  │                │   Agent   │──── Ed25519 keypair (/keys)
└─────────────┘                │           │
                               └─────┬─────┘
┌─────────────┐     tickets    ┌─────┴─────┐
│  Ticketing  │◄───────────────│ PostgreSQL│
│  (ServiceNow│                │           │
│   mock)     │                │ evidence  │
└─────────────┘                │ ctrl_runs │
                               │ trust_env │
┌─────────────┐     reads      └─────┬─────┘
│  Dashboard  │◄───────────────┘
│ (Streamlit) │
└─────────────┘
```

| Service | Port | Description |
|---------|------|-------------|
| `postgres` | 5432 | Evidence store + Keycloak backing DB |
| `keycloak` | 8080 | Identity provider (simulates Saviynt) |
| `ticketing` | 8001 | Mock ticketing API (simulates ServiceNow) |
| `agent` | — | Evidence collection, signing, envelope generation |
| `dashboard` | 8501 | Streamlit compliance dashboard |

## Cryptographic stack

- **Ed25519** — asymmetric signing; keypair generated on first agent start, persisted to a Docker volume (`agent_keys`). Public key used for verification; private key never leaves the volume.
- **SHA-256 Merkle tree** — append-only tree over all evidence items. Domain-separated: leaves prefixed `0x00`, pairs prefixed `0x01`. Every Trust Envelope embeds the current Merkle root; inclusion proofs are verifiable independently on the Evidence page.

## Trust levels

| Level | Confidence |
|-------|-----------|
| VERIFIED | ≥ 95% |
| HIGH | 75 – 94% |
| MEDIUM | 55 – 74% |
| LOW | 30 – 54% |
| CRITICAL | < 30% |

## Quick start

**Prerequisites:** Docker Desktop (or Docker Engine + Compose v2)

```bash
# 1. Clone
git clone https://github.com/CaptCanuck7/meridian_ccm.git
cd meridian_ccm

# 2. Configure (defaults work out of the box)
cp .env.example .env

# 3. Build and start all services
docker compose up --build

# 4. Open the dashboard
#    http://localhost:8501
#
# Keycloak admin console (optional):
#    http://localhost:8080  (admin / admin)
```

The agent seeds Keycloak with test users on first run, then begins collecting evidence. Allow ~60 seconds for the first envelopes to appear.

## Dashboard pages

| Page | Description |
|------|-------------|
| **Overview** | All Trust Envelopes across every control and product |
| **By Product** | Envelopes grouped by P1 / P2 |
| **Deviations** | Open failing items with ticket links and recommended actions |
| **Evidence** | Raw evidence log with Merkle proof verification per item |

All pages share a 6-card KPI row: Envelopes · Evidence Items · Claims Evaluated · Satisfied · Deviations · Open Tickets.

## Project structure

```
meridian_ccm/
├── config/
│   ├── controls.yaml        # Control definitions and framework mappings
│   └── products.yaml        # Product registry (P1, P2)
├── postgres/
│   └── init.sql             # DB initialisation (creates keycloak DB)
├── services/
│   ├── agent/               # Evidence agent
│   │   ├── crypto/
│   │   │   ├── keys.py      # Ed25519 KeyPair
│   │   │   └── merkle.py    # SHA-256 Merkle tree
│   │   ├── checks.py        # Control check functions
│   │   ├── claims.py        # Claims layer (Claim dataclass + ClaimResult)
│   │   ├── envelope.py      # TrustEnvelope + TrustLevel scoring
│   │   ├── db.py            # PostgreSQL helpers
│   │   ├── main.py          # Agent run loop
│   │   └── seed.py          # Keycloak test-data seeder
│   ├── dashboard/
│   │   └── app.py           # Streamlit dashboard (1300+ lines)
│   └── ticketing/
│       └── main.py          # FastAPI mock ticketing service
├── docker-compose.yml
└── .env.example
```

## Configuration

Controls and products are defined in plain YAML — no code changes needed to adjust thresholds, SLAs, or framework mappings.

**`config/controls.yaml`** — key parameters per control:

| Control | Key param | Default |
|---------|-----------|---------|
| LA.01 | `lookback_days` | 30 |
| LA.02 | `sla_days` | 1 |
| LA.03 | `max_days_since_uar` | 90 |
| LA.04 | `max_admins` | 3 |

**`config/products.yaml`** — maps products to the controls they are governed by.

## Terminology

This project uses **Deviations** (not "Exceptions") for failing control findings — consistent throughout code, UI, and database fields.

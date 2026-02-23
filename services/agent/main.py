"""
Meridian Evidence Collection Agent
===================================
Main entry point.  On startup:
  1. Loads (or generates) an Ed25519 keypair from /keys.
  2. Waits for Postgres, Keycloak, and the ticketing service to be ready.
  3. Ensures the DB schema exists.
  4. Reconstructs the Merkle tree from persisted leaf hashes.
  5. Runs a full control-evaluation cycle:
       a. Runs each control check (CheckResult)
       b. Signs the evidence payload with Ed25519
       c. Appends the evidence to the Merkle tree, stores in DB
       d. Builds a signed Claim from the CheckResult
       e. Builds a signed TrustEnvelope per product that has this control
       f. Stores TrustEnvelopes in DB
       g. Creates/deduplicates tickets for failing controls
  6. Sleeps for run_interval_seconds, then repeats indefinitely.

Environment variables (all have sane defaults for local dev):
  KEYCLOAK_URL          http://keycloak:8080
  KEYCLOAK_ADMIN        admin
  KEYCLOAK_ADMIN_PASS   admin
  TICKETING_URL         http://ticketing:8001
  POSTGRES_DSN          postgresql://meridian:meridian@postgres:5432/meridian
  KEY_DIR               /keys
  CONFIG_PATH           /config/controls.yaml
  PRODUCTS_PATH         /config/products.yaml
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

import psycopg2
import yaml
from tenacity import before_sleep_log, retry, stop_after_delay, wait_exponential

import checks as chk
import db
import signer
from claims import build_claim
from crypto.keys import KeyPair
from crypto.merkle import MerkleTree
from envelope import DisclosureLevel, build_trust_envelope
from keycloak_client import KeycloakClient
from ticketer import TicketingClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("meridian.agent")

# ── Config ────────────────────────────────────────────────────────────────────

KEYCLOAK_URL        = os.getenv("KEYCLOAK_URL",       "http://keycloak:8080")
KEYCLOAK_ADMIN      = os.getenv("KEYCLOAK_ADMIN",      "admin")
KEYCLOAK_ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS", "admin")
TICKETING_URL       = os.getenv("TICKETING_URL",       "http://ticketing:8001")
POSTGRES_DSN        = os.getenv("POSTGRES_DSN",        "postgresql://meridian:meridian@postgres:5432/meridian")
KEY_DIR             = os.getenv("KEY_DIR",             "/keys")
CONFIG_PATH         = os.getenv("CONFIG_PATH",         "/config/controls.yaml")
PRODUCTS_PATH       = os.getenv("PRODUCTS_PATH",       "/config/products.yaml")


def load_config(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def load_products(path: str) -> dict:
    try:
        with open(path) as fh:
            return yaml.safe_load(fh)
    except FileNotFoundError:
        return {"products": []}


# ── Startup retries ───────────────────────────────────────────────────────────

@retry(
    wait=wait_exponential(multiplier=2, min=2, max=30),
    stop=stop_after_delay(300),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=True,
)
def wait_for_postgres(dsn: str) -> "psycopg2.connection":
    log.info("Connecting to Postgres …")
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    log.info("Postgres ready.")
    return conn


@retry(
    wait=wait_exponential(multiplier=2, min=2, max=30),
    stop=stop_after_delay(300),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=True,
)
def wait_for_keycloak(kc: KeycloakClient) -> None:
    log.info("Waiting for Keycloak …")
    kc.ping()


@retry(
    wait=wait_exponential(multiplier=2, min=2, max=30),
    stop=stop_after_delay(120),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=True,
)
def wait_for_ticketing(tc: TicketingClient) -> None:
    log.info("Waiting for ticketing service …")
    tc.ping()


# ── Evidence collection ────────────────────────────────────────────────────────

def run_cycle(
    config: dict,
    products_cfg: dict,
    kc: KeycloakClient,
    tc: TicketingClient,
    conn: "psycopg2.connection",
    key_pair: KeyPair,
    merkle_tree: MerkleTree,
) -> None:
    realm    = config["agent"]["realm"]
    controls = config["controls"]
    products = products_cfg.get("products", [])

    # Build a map: control_id → list of product_ids that include it
    ctrl_products: dict[str, list[str]] = {}
    for p in products:
        for cid in p.get("controls", []):
            ctrl_products.setdefault(cid, []).append(p["id"])

    run_start = datetime.now(timezone.utc).isoformat()

    log.info("=== Starting control run (%d controls) ===", len(controls))

    for ctrl in controls:
        ctrl_id    = ctrl["id"]
        ctrl_name  = ctrl["name"]
        check_name = ctrl["check"]
        severity   = ctrl.get("severity", "medium")
        params     = ctrl.get("params", {})
        product_ids = ctrl_products.get(ctrl_id, [])

        check_fn = chk.REGISTRY.get(check_name)
        if check_fn is None:
            log.error("Unknown check '%s' for control %s — skipping", check_name, ctrl_id)
            continue

        log.info("Running %s (%s) …", ctrl_id, check_name)

        try:
            result: chk.CheckResult = check_fn(kc, params, realm=realm)
        except Exception as exc:
            log.exception("Check %s raised unexpectedly: %s", ctrl_id, exc)
            result = chk.CheckResult("error", {"error": str(exc)})

        # ── Build and sign evidence payload ────────────────────────────────
        evidence_payload = {
            "control_id":   ctrl_id,
            "control_name": ctrl_name,
            "check":        check_name,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collector":    "meridian-agent",
            "realm":        realm,
            "status":       result.status,
            "summary":      result.summary,
        }
        sig = signer.sign(evidence_payload)

        # ── Append to Merkle tree ──────────────────────────────────────────
        leaf_hash    = merkle_tree.append(evidence_payload)
        leaf_index   = merkle_tree.count - 1

        # ── Persist evidence ───────────────────────────────────────────────
        evidence_id = db.insert_evidence(
            conn, ctrl_id, check_name, evidence_payload, sig,
            merkle_leaf_hash=leaf_hash,
            merkle_index=leaf_index,
        )

        # ── Build and sign Claim ───────────────────────────────────────────
        claim = build_claim(result, evidence_id, ctrl, key_pair, product_ids)

        # ── Build and sign TrustEnvelope per product ───────────────────────
        for pid in product_ids:
            try:
                envelope = build_trust_envelope(
                    ctrl=ctrl,
                    product_id=pid,
                    claims=[claim],
                    merkle_tree=merkle_tree,
                    key_pair=key_pair,
                    collection_window_start=run_start,
                    disclosure_level=DisclosureLevel.FULL,
                )
                db.insert_trust_envelope(conn, envelope)
                log.info(
                    "  Envelope %s [%s] stored for %s/%s (confidence=%.2f)",
                    envelope.envelope_id[:8],
                    envelope.trust_level.value,
                    ctrl_id, pid,
                    envelope.composite_confidence,
                )
            except Exception as exc:
                log.error("Failed to build/store envelope for %s/%s: %s", ctrl_id, pid, exc)

        # ── Ticketing logic ────────────────────────────────────────────────
        ticket_number: str | None = None
        ticket_sys_id: str | None = None

        if result.status == "fail":
            last_ticket_number = db.get_last_ticket(conn, ctrl_id)
            create_new = True

            if last_ticket_number:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT ticket_sys_id FROM control_runs
                        WHERE control_id = %s AND ticket_sys_id IS NOT NULL
                        ORDER BY run_at DESC LIMIT 1
                        """,
                        (ctrl_id,),
                    )
                    row = cur.fetchone()
                last_sys_id = row[0] if row else None

                if last_sys_id and tc.is_ticket_open(last_sys_id):
                    log.info(
                        "%s: open ticket %s already exists — skipping creation",
                        ctrl_id, last_ticket_number,
                    )
                    ticket_number = last_ticket_number
                    ticket_sys_id = last_sys_id
                    create_new = False

            if create_new:
                try:
                    ticket = tc.create_ticket(
                        control_id=ctrl_id,
                        short_description=result.short_description,
                        description=result.description,
                        severity=severity,
                        evidence_id=evidence_id,
                    )
                    ticket_number = ticket["number"]
                    ticket_sys_id = ticket["sys_id"]
                except Exception as exc:
                    log.error("Failed to create ticket for %s: %s", ctrl_id, exc)

        db.insert_run(
            conn,
            ctrl_id,
            result.status,
            evidence_id,
            result.summary,
            ticket_number,
            ticket_sys_id,
        )

        status_icon = {"pass": "✓", "fail": "✗", "error": "!"}.get(result.status, "?")
        log.info(
            "%s %s [%s]%s",
            status_icon,
            ctrl_id,
            result.status.upper(),
            f" → {ticket_number}" if ticket_number else "",
        )

    log.info(
        "=== Run complete — Merkle tree has %d leaves, root=%s ===",
        merkle_tree.count,
        (merkle_tree.root or "none")[:16],
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("Meridian agent starting …")

    config       = load_config(CONFIG_PATH)
    products_cfg = load_products(PRODUCTS_PATH)
    interval     = config["agent"].get("run_interval_seconds", 300)
    realm        = config["agent"]["realm"]

    # ── Ed25519 keypair ────────────────────────────────────────────────────
    private_key_path = os.path.join(KEY_DIR, "signing_key.pem")
    public_key_path  = os.path.join(KEY_DIR, "signing_key.pub.pem")
    key_pair = KeyPair.load_or_generate(private_key_path, public_key_path)
    signer.init(key_pair)
    log.info("Ed25519 public key: %s", key_pair.public_key_hex)

    kc = KeycloakClient(
        KEYCLOAK_URL,
        realm=realm,
        admin_user=KEYCLOAK_ADMIN,
        admin_password=KEYCLOAK_ADMIN_PASS,
    )
    tc = TicketingClient(TICKETING_URL)

    # Wait for all dependencies
    conn = wait_for_postgres(POSTGRES_DSN)
    wait_for_keycloak(kc)
    wait_for_ticketing(tc)

    # Ensure schema exists (idempotent)
    db.ensure_schema(conn)

    # ── Reconstruct Merkle tree from persisted leaves ──────────────────────
    merkle_tree = MerkleTree()
    existing_leaves = db.get_evidence_leaf_hashes(conn)
    for lh in existing_leaves:
        merkle_tree.append_leaf_hash(lh)
    log.info(
        "Merkle tree reconstructed: %d existing leaves, root=%s",
        merkle_tree.count,
        (merkle_tree.root or "empty")[:16] if merkle_tree.root else "empty",
    )

    log.info("All dependencies ready. Run interval: %ds", interval)

    while True:
        try:
            run_cycle(config, products_cfg, kc, tc, conn, key_pair, merkle_tree)
        except Exception as exc:
            log.exception("Unhandled error in run cycle: %s", exc)
            try:
                conn.close()
            except Exception:
                pass
            conn = wait_for_postgres(POSTGRES_DSN)

        log.info("Sleeping %ds until next run …", interval)
        time.sleep(interval)


if __name__ == "__main__":
    main()

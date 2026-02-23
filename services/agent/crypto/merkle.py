"""
Append-only SHA-256 Merkle tree for OTVP evidence chaining.

Every evidence item is hashed as a leaf. The tree can be reconstructed
from the ordered list of leaf hashes stored in the database, so it
survives agent restarts.

Proof format:
  {
    "leaf_hash":   "<hex>",
    "index":       <int>,
    "proof_hashes": [{"hash": "<hex>", "position": "left"|"right"}, ...],
    "root_hash":   "<hex>",
  }
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_leaf(item: dict) -> str:
    """SHA-256 of the canonical JSON representation of an evidence item."""
    canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return _sha256(b"\x00" + canonical)   # domain-separate leaves


def _hash_pair(left: str, right: str) -> str:
    """SHA-256 of two sibling hashes concatenated (domain-separated)."""
    return _sha256(b"\x01" + left.encode() + right.encode())


def _next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    p = 1
    while p < n:
        p <<= 1
    return p


def _build_tree(leaves: list[str]) -> list[list[str]]:
    """
    Build a complete binary Merkle tree from leaf hashes.
    Returns a list of levels: levels[0] = leaves, levels[-1] = [root].
    Odd-length levels duplicate the last element before hashing.
    """
    if not leaves:
        return []
    levels: list[list[str]] = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2 != 0:
            current = current + [current[-1]]
        parents = [_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        levels.append(parents)
    return levels


class MerkleTree:
    """
    Append-only Merkle tree.

    Usage:
        tree = MerkleTree()
        # Optionally seed with persisted leaf hashes from DB:
        tree.load_leaves(["abc123...", "def456..."])
        # Add new evidence items:
        leaf = tree.append(evidence_dict)
        proof = tree.get_proof(tree.count - 1)
        assert MerkleTree.verify_proof(proof["leaf_hash"], proof["proof_hashes"], proof["root_hash"])
    """

    def __init__(self) -> None:
        self._leaves: list[str] = []

    # ── Population ───────────────────────────────────────────────────────────

    def load_leaves(self, leaf_hashes: list[str]) -> None:
        """Seed tree from persisted leaf hashes (ordered by merkle_index)."""
        self._leaves = list(leaf_hashes)

    def append(self, item: dict) -> str:
        """
        Hash item as a new leaf and append to the tree.
        Returns the leaf hash.
        """
        leaf_hash = _hash_leaf(item)
        self._leaves.append(leaf_hash)
        return leaf_hash

    def append_leaf_hash(self, leaf_hash: str) -> None:
        """Append a pre-computed leaf hash (used when loading from DB)."""
        self._leaves.append(leaf_hash)

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def count(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> str | None:
        if not self._leaves:
            return None
        levels = _build_tree(self._leaves)
        return levels[-1][0]

    # ── Proof generation / verification ──────────────────────────────────────

    def get_proof(self, index: int) -> dict[str, Any]:
        """
        Generate a Merkle inclusion proof for the leaf at `index`.

        Returns a dict with leaf_hash, index, proof_hashes, and root_hash.
        The proof can be verified independently with MerkleTree.verify_proof().
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Merkle proof index {index} out of range (tree has {len(self._leaves)} leaves)")

        levels = _build_tree(self._leaves)
        proof_hashes: list[dict[str, str]] = []
        idx = index

        for level in levels[:-1]:          # skip root level
            padded = level + ([level[-1]] if len(level) % 2 != 0 else [])
            if idx % 2 == 0:
                sibling_idx = idx + 1
                position = "right"
            else:
                sibling_idx = idx - 1
                position = "left"
            proof_hashes.append({"hash": padded[sibling_idx], "position": position})
            idx //= 2

        return {
            "leaf_hash":   self._leaves[index],
            "index":       index,
            "proof_hashes": proof_hashes,
            "root_hash":   levels[-1][0],
        }

    @staticmethod
    def verify_proof(
        leaf_hash: str,
        proof_hashes: list[dict[str, str]],
        root_hash: str,
    ) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf_hash:   SHA-256 hex of the leaf.
            proof_hashes: Ordered list of {"hash": ..., "position": "left"|"right"}.
            root_hash:   Expected Merkle root.
        """
        current = leaf_hash
        for step in proof_hashes:
            sibling = step["hash"]
            if step["position"] == "right":
                current = _hash_pair(current, sibling)
            else:
                current = _hash_pair(sibling, current)
        return current == root_hash

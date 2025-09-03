"""Fuzz harness for Merkle tree construction & inclusion proof verification."""
from __future__ import annotations
import atheris
import sys
import hashlib

with atheris.instrument_imports():
    from signet_api.merkle import MerkleTree, verify_inclusion


def TestOneInput(data: bytes):  # noqa: N802
    if not data:
        return
    # Split data deterministically into pseudo-leaves (bounded count)
    # Use fixed-size chunks to avoid quadratic blowups.
    size = max(1, min(32, data[0]))
    chunks = [data[i : i + size] for i in range(1, min(len(data), 1 + size * 32), size)]
    # Hash chunks to normalize length & distribution
    leaves = [hashlib.sha256(c).digest() for c in chunks if c]
    if len(leaves) < 2:
        return
    try:
        tree = MerkleTree.from_leaves(leaves)
    except ValueError:
        return
    # Pick an index based on trailing byte
    idx = data[-1] % len(leaves)
    proof = tree.inclusion_proof(idx)
    leaf = leaves[idx]
    ok = verify_inclusion(leaf, idx, proof, tree.root)
    if not ok:
        raise RuntimeError("valid inclusion proof failed")


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

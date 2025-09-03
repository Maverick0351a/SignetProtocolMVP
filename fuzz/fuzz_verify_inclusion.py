"""Higher-level inclusion proof fuzzing with mutated proofs."""
from __future__ import annotations
import atheris
import sys
import hashlib
import random

with atheris.instrument_imports():
    from signet_api.merkle import MerkleTree, verify_inclusion


def TestOneInput(data: bytes):  # noqa: N802
    if len(data) < 8:
        return
    # Derive variable chunk size & mutation seed
    seed = int.from_bytes(data[:4], 'little')
    random.seed(seed)
    chunk_len = 1 + (data[4] % 32)
    body = data[5:]
    leaves_raw = [body[i:i+chunk_len] for i in range(0, min(len(body), chunk_len * 16), chunk_len)]
    leaves = [hashlib.sha256(x).digest() for x in leaves_raw if x]
    if len(leaves) < 3:
        return
    try:
        tree = MerkleTree.from_leaves(leaves)
    except ValueError:
        return
    idx = seed % len(leaves)
    proof = list(tree.inclusion_proof(idx))
    # With some probability, mutate one sibling to exercise negative path
    if random.random() < 0.2 and proof:
        sib, side = proof[0]
        mutated = bytes([(sib[0] ^ 0x01)]) + sib[1:]
        proof[0] = (mutated, side)
        ok = verify_inclusion(leaves[idx], idx, proof, tree.root)
        if ok:
            raise RuntimeError("tampered proof unexpectedly verified")
    else:
        ok = verify_inclusion(leaves[idx], idx, proof, tree.root)
        if not ok:
            raise RuntimeError("valid proof failed")


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

from signet_api.merkle import MerkleTree, verify_inclusion
import hashlib


def test_merkle_basic():
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(5)]
    tree = MerkleTree.from_leaves(leaves)
    assert tree.root
    proof = tree.inclusion_proof(2)
    assert verify_inclusion(leaves[2], 2, proof, tree.root)


def test_merkle_tamper_detection():
    """Flipping a sibling hash in the proof should cause verification to fail."""
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(6)]
    tree = MerkleTree.from_leaves(leaves)
    idx = 3
    proof = tree.inclusion_proof(idx)
    assert verify_inclusion(leaves[idx], idx, proof, tree.root)
    # Tamper: flip first bit of first sibling hash
    tampered = []
    for i, (sib, side) in enumerate(proof):
        if i == 0:
            b = bytearray(sib)
            b[0] ^= 0x01
            sib = bytes(b)
        tampered.append((sib, side))
    assert not verify_inclusion(leaves[idx], idx, tampered, tree.root)

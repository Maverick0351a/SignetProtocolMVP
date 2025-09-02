from signet_api.merkle import MerkleTree, verify_inclusion
import hashlib


def test_merkle_basic():
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(5)]
    tree = MerkleTree.from_leaves(leaves)
    assert tree.root
    proof = tree.inclusion_proof(2)
    assert verify_inclusion(leaves[2], 2, proof, tree.root)

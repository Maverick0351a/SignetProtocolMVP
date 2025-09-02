from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import List, Tuple


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclass
class MerkleTree:
    leaves: List[bytes]
    levels: List[List[bytes]]  # level 0 = leaves

    @classmethod
    def from_leaves(cls, leaves: List[bytes]) -> "MerkleTree":
        if not leaves:
            raise ValueError("no leaves")
        lvl = [leaf for leaf in leaves]
        levels = [lvl]
        while len(lvl) > 1:
            nxt = []
            for i in range(0, len(lvl), 2):
                a = lvl[i]
                b = lvl[i + 1] if i + 1 < len(lvl) else lvl[i]  # duplicate last if odd
                nxt.append(_h(a + b))
            levels.append(nxt)
            lvl = nxt
        return cls(leaves, levels)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def inclusion_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """Return list of (sibling_hash, 'L'|'R') from leaf to root."""
        proof = []
        idx = index
        for level in self.levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx >= len(level):
                sibling = level[idx]
            else:
                sibling = level[sibling_idx]
            proof.append((sibling, "L" if is_right else "R"))
            idx //= 2
        return proof


def verify_inclusion(
    leaf: bytes, index: int, proof: List[Tuple[bytes, str]], root: bytes
) -> bool:
    h = leaf
    idx = index
    for sibling, side in proof:
        if side == "L":
            h = _h(sibling + h)
        else:
            h = _h(h + sibling)
        idx //= 2
    return h == root

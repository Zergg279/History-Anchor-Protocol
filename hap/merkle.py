from __future__ import annotations

from dataclasses import dataclass

from .codec import sha256


@dataclass(frozen=True)
class ProofStep:
    sibling: str
    side: str  # "left" or "right"

    def as_dict(self) -> dict[str, str]:
        return {"sibling": self.sibling, "side": self.side}


def _leaf(record_id: str) -> bytes:
    raw = bytes.fromhex(record_id)
    if len(raw) != 32:
        raise ValueError("record_id must be a 32-byte hex digest")
    return raw


def merkle_root(record_ids: list[str]) -> str:
    if not record_ids:
        return "00" * 32
    level = [_leaf(item) for item in record_ids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(record_ids: list[str], index: int) -> list[dict[str, str]]:
    if index < 0 or index >= len(record_ids):
        raise IndexError("record index out of range")
    level = [_leaf(item) for item in record_ids]
    position = index
    proof: list[ProofStep] = []

    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling_index = position - 1 if position % 2 else position + 1
        sibling_side = "left" if sibling_index < position else "right"
        proof.append(ProofStep(level[sibling_index].hex(), sibling_side))
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2

    return [step.as_dict() for step in proof]


def verify_merkle_proof(
    record_id: str, proof: list[dict[str, str]], expected_root: str
) -> bool:
    try:
        value = _leaf(record_id)
        for step in proof:
            sibling = bytes.fromhex(step["sibling"])
            if len(sibling) != 32:
                return False
            if step["side"] == "left":
                value = sha256(sibling + value)
            elif step["side"] == "right":
                value = sha256(value + sibling)
            else:
                return False
        return value.hex() == expected_root
    except (KeyError, TypeError, ValueError):
        return False

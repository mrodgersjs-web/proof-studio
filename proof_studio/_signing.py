"""Thin wrappers around the rigforge ProofPacket sealing helpers.

Kept in one place so the scenario builders stay about scenarios: seal() signs a
packet with a given demo material value, and reforge() recomputes a packet hash
without re-signing, which is the forgery step a tamper vector performs.
"""

from __future__ import annotations

from ._vendor import ensure_rigforge

ensure_rigforge()

from rigforge.proof import ProofPacket  # noqa: E402


def seal(packet: ProofPacket, material: bytes) -> ProofPacket:
    """Return the packet sealed with the given demo material value."""
    return packet.sealed(signing_key=material)


def reforge(packet: ProofPacket) -> ProofPacket:
    """Recompute the packet hash without re-signing (the tamper's move)."""
    return packet.model_copy(update={"packet_sha256": packet.compute_hash()})

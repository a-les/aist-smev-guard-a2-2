# src/vipnet/__init__.py
# Владелец: Селезнева О. С. (@wauwho), Панфилов А. В. (@yo5hh) — Команда А2.2
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.vipnet.ast_opa_uzi_engine import VipnetAstAndUziEngine
    from src.vipnet.z3_smt_tunnel_verifier import (
        PROTO_CODE_MAP,
        Box3D,
        Z3VipnetSmtVerifier,
        verify_config_text,
    )

__all__ = [
    "PROTO_CODE_MAP",
    "Box3D",
    "VipnetAstAndUziEngine",
    "Z3VipnetSmtVerifier",
    "verify_config_text",
]


def __getattr__(name: str) -> Any:
    if name == "VipnetAstAndUziEngine":
        import src.vipnet.ast_opa_uzi_engine as mod_ast

        return getattr(mod_ast, name)
    import src.vipnet.z3_smt_tunnel_verifier as mod_z3

    val = getattr(mod_z3, name, None)
    if val is not None:
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

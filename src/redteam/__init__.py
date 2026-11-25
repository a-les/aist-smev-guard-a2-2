# src/redteam/__init__.py
# Владелец: Панфилов Алексей Владимирович (@yo5hh, SC @nyamskiy) — Команда А2.2
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.redteam.gov_garak_pyrit_orchestrator import (
        Base64Converter,
        BureaucraticAuthorityConverter,
        CompositeConverter,
        GovGarakPyritOrchestrator,
        HomoglyphConverter,
        LeetspeakConverter,
        PromptConverter,
        RedTeamCampaignReport,
        RedTeamProbeResult,
        RedTeamProbeSpec,
        Rot13Converter,
    )

__all__ = [
    "Base64Converter",
    "BureaucraticAuthorityConverter",
    "CompositeConverter",
    "GovGarakPyritOrchestrator",
    "HomoglyphConverter",
    "LeetspeakConverter",
    "PromptConverter",
    "RedTeamCampaignReport",
    "RedTeamProbeResult",
    "RedTeamProbeSpec",
    "Rot13Converter",
]


def __getattr__(name: str) -> Any:
    import src.redteam.gov_garak_pyrit_orchestrator as mod

    val = getattr(mod, name, None)
    if val is not None:
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# src/models/contracts.py
# Совместный контракт данных между модулями Селезневой О. С. (@wauwho) и Панфилова А. В. (@yo5hh)
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class PiiEntityCategory(str, Enum):
    PERSON_FIO = "PERSON"
    SNILS = "SNILS"
    INN_FL = "INN_FL"
    INN_UL = "INN_UL"
    OGRN = "OGRN"
    OGRNIP = "OGRNIP"
    PASSPORT_RF = "PASSPORT"
    OMS_POLICY = "OMS"
    BANK_CARD_MIR = "BANK_CARD"
    BANK_ACCOUNT_20D = "BANK_ACCOUNT"
    CADASTRAL_NUM = "CADASTRAL"
    UIN_GIS_GMP = "UIN"
    PHONE_RU = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS_OMSK = "ADDRESS"
    MEDICAL_SPECIAL_152FZ = "MEDICAL_SPEC"


class SourceSpan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(..., min_length=1)
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)


class DetectedPiiSpan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    category: PiiEntityCategory
    raw_value: str = Field(..., min_length=1)
    normalized_value: str = Field(..., min_length=1)
    char_start: int = Field(..., ge=0)
    char_end: int = Field(..., gt=0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    checksum_verified: bool = Field(default=False)
    detector_source: Literal["MATH_CHECKSUM", "ONNX_MODERNBERT_NER", "HYBRID_ENSEMBLE"]


class TokenizedPromptBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    citizen_session_id: str = Field(..., min_length=8, max_length=128)
    department_mandate: str = Field(..., min_length=2, max_length=64)
    sanitized_text: str
    token_count: int = Field(..., ge=0)
    detected_categories: list[PiiEntityCategory] = Field(default_factory=list)
    token_map_fingerprints: dict[str, str] = Field(default_factory=dict)
    expires_at_utc: datetime


class SmevAttachmentMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(..., min_length=1, max_length=255)
    mime_type: str = Field(..., min_length=3, max_length=128)
    size_bytes: int = Field(..., ge=1, le=15 * 1024 * 1024)
    sha256_hex: str = Field(..., min_length=64, max_length=64)
    extracted_text: str = Field(default="")


class SmevAppealEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(..., min_length=8, max_length=64)
    citizen_session_id: str = Field(..., min_length=8, max_length=128)
    sender_mnemonic: str = Field(..., pattern=r"^[A-Z0-9_]{3,32}$")
    recipient_mnemonic: str = Field(default="GUIT_OMSK_AIST_01")
    department_mandate: str = Field(default="OMSK_GUIT_59FZ_OPERATOR")
    service_code: str = Field(default="59FZ_CITIZEN_APPEAL")
    appeal_subject: str = Field(..., min_length=3, max_length=500)
    appeal_body: str = Field(..., min_length=5, max_length=50000)
    attachments: list[SmevAttachmentMeta] = Field(default_factory=list)
    raw_xml_envelope: str | None = Field(default=None)


class PromptShieldVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_blocked: bool
    triggered_stage: Literal[
        "NONE",
        "STAGE1_UNICODE_DECODE",
        "STAGE2_ONNX_BGE_CLASSIFIER",
        "STAGE3_OUTPUT_CANARY_GUARD",
    ]
    risk_score: float = Field(..., ge=0.0, le=1.0)
    attack_family: str = Field(default="BENIGN")
    normalized_text: str
    explanation: str
    canary_leaked: bool = Field(default=False)
    illegal_commitment_detected: bool = Field(default=False)
    latency_ms: float = Field(..., ge=0.0)


class SecurityRuleNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    section: Literal["local", "forward", "tunnel", "nat"]
    priority: int = Field(..., ge=1)
    subject_cidr_or_role: str
    resource_cidr_or_uri: str
    protocol_or_method: Literal["tcp", "udp", "icmp", "ip", "any"] = "tcp"
    port_range: tuple[int, int] = (0, 65535)
    effect: Literal["allow", "deny", "encrypt_tunnel"]
    mtu_value: int = Field(default=1360, ge=576, le=9000)
    span: SourceSpan

    @field_validator("port_range")
    @classmethod
    def _validate_ports(cls, v: tuple[int, int]) -> tuple[int, int]:
        low, high = v
        if not (0 <= low <= high <= 65535):
            raise ValueError(f"Некорректный диапазон портов: {v}")
        return v


class VerificationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    cwe_id: str
    fstec_measure: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    z3_counterexample: dict[str, str | int] | None = None
    suggested_patch_diff: str | None = None
    span: SourceSpan


class FstecUziReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gis_class: Literal["K1", "K2", "K3"] = "K1"
    i_block_multiplier: float = Field(..., ge=0.0, le=1.0)
    operational_weighted_score: float = Field(..., ge=0.0, le=1.0)
    final_uzi: float = Field(..., ge=0.0, le=1.0)
    compliance_status: Literal[
        "COMPLIANT_K1",
        "NON_COMPLIANT_BLOCKED",
        "NON_COMPLIANT_LOW_SCORE",
    ]
    opa_denials: list[str] = Field(default_factory=list)
    group_averages: dict[str, float] = Field(default_factory=dict)


class StreebogAuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq_id: int = Field(..., ge=1)
    occurred_at: datetime
    actor: str = Field(..., min_length=2, max_length=128)
    citizen_session_id: str = Field(..., min_length=2, max_length=128)
    event_type: str = Field(..., min_length=3, max_length=96)
    fstec_measure: str = Field(default="РСБ.1 / ГОСТ Р 59548-2022")
    severity: Literal["INFO", "WARNING", "HIGH", "CRITICAL"]
    payload_summary: dict[str, Any]
    prev_hash: str = Field(..., min_length=64, max_length=64)
    streebog256_hash: str = Field(..., min_length=64, max_length=64)

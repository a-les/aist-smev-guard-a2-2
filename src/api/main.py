# src/api/main.py
# Совместный входной шлюз Команды А2.2 (Селезнева О. С. @wauwho + Панфилов А. В. @yo5hh)
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from src.crypto.fstec_streebog_audit_logger import FstecStreebogAuditLogger
from src.guardrails.three_stage_prompt_shield import ThreeStageGovPromptShield
from src.models.contracts import SmevAppealEnvelope
from src.pii.reversible_token_vault import (
    CrossCitizenLeakAttemptError,
    ReversiblePiiTokenVault,
)
from src.redteam.gov_garak_pyrit_orchestrator import GovGarakPyritOrchestrator
from src.smev.smev3_envelope_validator import (
    Smev3EnvelopeValidator,
    SmevSecurityViolationError,
)
from src.vipnet.ast_opa_uzi_engine import VipnetAstAndUziEngine
from src.vipnet.z3_smt_tunnel_verifier import Z3VipnetSmtVerifier

app = FastAPI(
    title="Щит-АИСТ / СМЭВ-Guard & ViPNet Z3 Gateway (Team A2.2)",
    version="2.0.0",
    description=(
        "Защищённый шлюз межведомственного электронного взаимодействия и безопасности ИИ-сервисов "
        "госсектора (152-ФЗ PII Tokenization + 3-Stage Prompt Shield + Z3 SMT + Стрибог-256)"
    ),
)

# Инициализация синглтонов ядра безопасности
smev_validator = Smev3EnvelopeValidator()
pii_vault = ReversiblePiiTokenVault()
prompt_shield = ThreeStageGovPromptShield()
audit_logger = FstecStreebogAuditLogger()
vipnet_uzi_engine = VipnetAstAndUziEngine()
z3_verifier = Z3VipnetSmtVerifier()
redteam_orchestrator = GovGarakPyritOrchestrator(shield=prompt_shield)

# Счётчики Prometheus для SOC-узла VM 225
METRICS_STATE: dict[str, float] = {
    "aist_guard_appeals_processed_total": 0.0,
    "aist_guard_pii_entities_tokenized_total": 0.0,
    "aist_guard_prompt_injections_blocked_total": 0.0,
    "aist_guard_cross_citizen_leak_attempts_blocked_total": 0.0,
    "aist_guard_fstec_uzi_score": 0.94,
    "aist_guard_streebog_chain_valid": 1.0,
}


class OperatorDeanonRequest(BaseModel):
    citizen_session_id: str = Field(..., min_length=8)
    operator_mandate: str = Field(..., min_length=2)
    operator_login: str = Field(..., min_length=2)
    tokenized_llm_reply: str = Field(..., min_length=1)


class VipnetAuditRequest(BaseModel):
    config_text: str = Field(..., min_length=10)
    measures_by_group: dict[str, list[float]] = Field(default_factory=dict)


@app.post("/v1/smev/process-appeal")
def process_smev_citizen_appeal(envelope: SmevAppealEnvelope) -> dict[str, Any]:
    """
    Полный 4-этапный конвейер защиты обращения гражданина:
    1) Валидация конверта и вложений СМЭВ 3.0 (анти-XXE, XML Bomb, SSRF, макросы);
    2) Проверка текста и вложений через 3-каскадный экран от Prompt Injection / RAG Poisoning;
    3) Гибридная детекция ПДн (СНИЛС/ИНН/Паспорт/Счёт/ФИО во всём конверте и вложениях)
       и обратимая токенизация в AES-256-GCM;
    4) Вызов LLM «АИСТ» с обезличенными токенами + проверка ответа Каскадом 3 (Canary Watcher).
    """
    try:
        smev_validator.validate_envelope(envelope)
    except SmevSecurityViolationError as exc:
        rec = audit_logger.append_security_event(
            actor=envelope.sender_mnemonic,
            citizen_session_id=envelope.citizen_session_id,
            event_type="SMEV3_PERIMETER_ATTACK_BLOCKED",
            severity="CRITICAL",
            payload_summary={"message_id": envelope.message_id, "reason": str(exc)},
            fstec_measure="ЗИС.3 / МСЭ.1",
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "SMEV3_SECURITY_VIOLATION", "reason": str(exc), "streebog256": rec.streebog256_hash},
        ) from exc

    attachment_texts = [a.extracted_text.strip() for a in envelope.attachments if a.extracted_text.strip()]
    combined_appeal_text = f"{envelope.appeal_subject}. {envelope.appeal_body}"
    if attachment_texts:
        combined_appeal_text = f"{combined_appeal_text}\n" + "\n".join(attachment_texts)

    ingress_verdict = prompt_shield.inspect_ingress_prompt(combined_appeal_text)
    if ingress_verdict.is_blocked:
        METRICS_STATE["aist_guard_prompt_injections_blocked_total"] += 1.0
        rec = audit_logger.append_security_event(
            actor=envelope.sender_mnemonic,
            citizen_session_id=envelope.citizen_session_id,
            event_type="GOV_PROMPT_INJECTION_BLOCKED",
            severity="HIGH",
            payload_summary={
                "message_id": envelope.message_id,
                "stage": ingress_verdict.triggered_stage,
                "attack_family": ingress_verdict.attack_family,
                "risk_score": ingress_verdict.risk_score,
            },
            fstec_measure="МД ФСТЭК 12.04.2026 ИИ",
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "GOV_PROMPT_INJECTION_BLOCKED",
                "verdict": ingress_verdict.model_dump(),
                "streebog256": rec.streebog256_hash,
            },
        )

    tokenized_bundle = pii_vault.tokenize_citizen_text(
        text=combined_appeal_text,
        citizen_session_id=envelope.citizen_session_id,
        department_mandate=envelope.department_mandate,
    )
    METRICS_STATE["aist_guard_pii_entities_tokenized_total"] += float(tokenized_bundle.token_count)
    METRICS_STATE["aist_guard_appeals_processed_total"] += 1.0

    # Формируем проект ответа в LLM «АИСТ» (на обезличенных токенах!)
    simulated_aist_llm_reply = (
        f"Уважаемый заявитель! Ваше обращение ({tokenized_bundle.sanitized_text}) "
        f"принято в обработку ГУИТ Омской области в соответствии с ФЗ № 59-ФЗ."
    )
    egress_verdict = prompt_shield.inspect_egress_llm_output(simulated_aist_llm_reply)
    if egress_verdict.is_blocked:
        rec = audit_logger.append_security_event(
            actor="AIST_LLM_ENGINE",
            citizen_session_id=envelope.citizen_session_id,
            event_type="LLM_OUTPUT_CANARY_OR_POLICY_BLOCKED",
            severity="CRITICAL",
            payload_summary={"reason": egress_verdict.explanation},
            fstec_measure="ЗИС.17 / ИИ.4",
        )
        raise HTTPException(
            status_code=502,
            detail={"error": "LLM_OUTPUT_BLOCKED", "reason": egress_verdict.explanation, "streebog256": rec.streebog256_hash},
        )

    rec = audit_logger.append_security_event(
        actor=envelope.sender_mnemonic,
        citizen_session_id=envelope.citizen_session_id,
        event_type="SMEV_APPEAL_TOKENIZED_AND_PROCESSED",
        severity="INFO",
        payload_summary={
            "message_id": envelope.message_id,
            "token_count": tokenized_bundle.token_count,
            "categories": [c.value for c in tokenized_bundle.detected_categories],
        },
        fstec_measure="152-ФЗ ст. 19 / РСБ.1",
    )
    return {
        "status": "OK",
        "message_id": envelope.message_id,
        "citizen_session_id": envelope.citizen_session_id,
        "sanitized_prompt_sent_to_aist": tokenized_bundle.sanitized_text,
        "tokenized_llm_draft_reply": simulated_aist_llm_reply,
        "pii_tokens_count": tokenized_bundle.token_count,
        "detected_categories": [c.value for c in tokenized_bundle.detected_categories],
        "audit_streebog256": rec.streebog256_hash,
    }


@app.post("/v1/operator/deanon")
def deanon_reply_for_operator(req: OperatorDeanonRequest) -> dict[str, Any]:
    """
    Обратная детокенизация ответа LLM «АИСТ» для авторизованного оператора ведомства
    с криптографической проверкой сессии гражданина и мандата доступа.
    """
    try:
        restored_text = pii_vault.detokenize_for_authorized_operator(
            llm_response_text=req.tokenized_llm_reply,
            citizen_session_id=req.citizen_session_id,
            operator_mandate=req.operator_mandate,
            strict_on_unknown_token=True,
        )
    except CrossCitizenLeakAttemptError as exc:
        METRICS_STATE["aist_guard_cross_citizen_leak_attempts_blocked_total"] += 1.0
        rec = audit_logger.append_security_event(
            actor=req.operator_login,
            citizen_session_id=req.citizen_session_id,
            event_type="CROSS_CITIZEN_PII_LEAK_ATTEMPT_BLOCKED",
            severity="CRITICAL",
            payload_summary={"operator_mandate": req.operator_mandate, "reason": str(exc)},
            fstec_measure="УПД.4 / 152-ФЗ ст. 19",
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "CROSS_CITIZEN_PII_LEAK_BLOCKED", "reason": str(exc), "streebog256": rec.streebog256_hash},
        ) from exc

    rec = audit_logger.append_security_event(
        actor=req.operator_login,
        citizen_session_id=req.citizen_session_id,
        event_type="OPERATOR_AUTHORIZED_PII_DETOKENIZATION",
        severity="INFO",
        payload_summary={"operator_mandate": req.operator_mandate},
    )
    return {
        "status": "OK",
        "restored_official_reply": restored_text,
        "audit_streebog256": rec.streebog256_hash,
    }


@app.post("/v1/vipnet/verify-uzi")
def verify_vipnet_and_calculate_uzi(req: VipnetAuditRequest) -> dict[str, Any]:
    """
    Запускает парсер конфигураций ViPNet (Селезнева О. С.), SMT-верификатор Z3 (Панфилов А. В.)
    и вычисляет двухконтурный показатель защищённости ГИС Узи по Приказу ФСТЭК № 117/137.
    """
    rules, tunnels = vipnet_uzi_engine.parse_vipnet_configs(req.config_text)
    z3_findings = z3_verifier.verify_rules_and_tunnels(rules, configured_tunnels=tunnels)
    has_leak = any(f.finding_id.startswith("Z3-LEAK-") for f in z3_findings)
    uzi_report = vipnet_uzi_engine.evaluate_opa_and_calculate_uzi(
        rules=rules,
        measures_by_group=req.measures_by_group,
        z3_has_cleartext_leak=has_leak,
    )
    METRICS_STATE["aist_guard_fstec_uzi_score"] = uzi_report.final_uzi
    sarif_doc = z3_verifier.export_to_sarif_210(z3_findings)
    return {
        "uzi_report": uzi_report.model_dump(),
        "z3_findings": [f.model_dump() for f in z3_findings],
        "sarif_210": sarif_doc,
    }


@app.get("/v1/audit/verify-chain")
def verify_streebog_audit_chain() -> dict[str, Any]:
    is_valid, broken_seq, message = audit_logger.verify_chain_integrity()
    METRICS_STATE["aist_guard_streebog_chain_valid"] = 1.0 if is_valid else 0.0
    return {
        "chain_valid": is_valid,
        "broken_seq_id": broken_seq,
        "message": message,
        "records_count": len(audit_logger.records),
        "merkle_root_streebog256": audit_logger.compute_merkle_root_streebog(),
    }


@app.get("/metrics")
def prometheus_metrics() -> Response:
    lines = [f"{k} {v}" for k, v in METRICS_STATE.items()]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

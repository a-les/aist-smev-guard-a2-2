# AGENTS.md — Инструкции для ИИ-агентов репозитория `aist-smev-guard-a2-2` (Команда А2.2)

## 1. Архитектурные инварианты и разделение ответственности (50 / 50)
- **Роль 1 — Селезнева Ольга Сергеевна (`@wauwho`, SC `@tmafles`)**:
  отвечает за пакеты `src/pii/`, `src/smev/`, `src/vipnet/ast_opa_uzi_engine.py`, `policies/fstec_117_guit.rego`,
  скрипты `pipelines/01_datatrove_ru_pii_and_injections_curation.py`,
  `pipelines/03_modernbert_token_classification_pii_onnx.py` и тесты `tests/test_pii_vault_and_checksums.py`.
- **Роль 2 — Панфилов Алексей Владимирович (`@yo5hh`, SC `@nyamskiy`)**:
  отвечает за пакеты `src/guardrails/`, `src/redteam/`, `src/vipnet/z3_smt_tunnel_verifier.py`,
  `src/crypto/fstec_streebog_audit_logger.py`, `migrations/001_smev_aist_guard_schema.sql`, `src/api/main.py`,
  скрипты `pipelines/02_distilabel_gov_redteam_and_pii_synth.py`,
  `pipelines/04_setfit_and_unsloth_dpo_guardrail.py` и тесты `tests/test_indirect_rag_injection_gov.py`.

## 2. Жёсткие запреты информационной безопасности (10.05.01 / ГИС К1)
1. **Запрет логирования открытых ПДн (152-ФЗ ст. 19):** ни одна функция не имеет права записывать сырые значения СНИЛС, ИНН, паспортов РФ, полисов ОМС, телефонов или ФИО в `fstec_security_audit_log` или stdout — в лог пишутся только токены `<SNILS_01>` или HMAC-отпечатки!
2. **Запрет межсессионного доступа (`0% Cross-Citizen PII Leak`):** детокенизация в `ReversiblePiiTokenVault` обязана проверять совпадение `citizen_session_id` и `department_mandate` через `AAD` в `AES-256-GCM`.
3. **Запрет стандартного `xml.etree` без фильтра DTD/ENTITY:** любой XML-конверт СМЭВ 3.0 обязан проходить предварительную фильтрацию `Smev3EnvelopeValidator._validate_raw_smev_xml`.
4. **Неизменяемость журнала ГОСТ Р 59548-2022:** все критические события шлюза обязаны подписываться 256-битным хешем ГОСТ Р 34.11-2012 («Стрибог-256») в `FstecStreebogAuditLogger`.

## 3. Команды обязательной проверки перед каждым коммитом
```bash
uv run ruff check src/ pipelines/ tests/
uv run pytest -v --tb=short
uv run python -m pipelines.05_gov_guard_eval_gate
```

-- migrations/001_smev_aist_guard_schema.sql
-- Совместная схема БД Команды А2.2 (Селезнева О. С. + Панфилов А. В.) для PostgreSQL 16 (VM 224)

BEGIN;

-- 1. Таблица сессионного криптографического хранилища токенов ПДн (152-ФЗ) с Row-Level Security (RLS)
CREATE TABLE IF NOT EXISTS pii_token_vault (
    vault_entry_id BIGSERIAL PRIMARY KEY,
    citizen_session_id VARCHAR(128) NOT NULL,
    department_mandate VARCHAR(64) NOT NULL,
    token_placeholder VARCHAR(32) NOT NULL,
    pii_category VARCHAR(32) NOT NULL,
    value_hmac_fingerprint CHAR(64) NOT NULL,
    nonce_b64 VARCHAR(32) NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    aad_b64 TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at_utc TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_session_token UNIQUE (citizen_session_id, token_placeholder)
);

CREATE INDEX IF NOT EXISTS idx_pii_vault_session_expires
    ON pii_token_vault (citizen_session_id, expires_at_utc);

-- Включаем принудительную изоляцию строк (RLS) по текущей сессии гражданина (0% Cross-Citizen Leak на уровне СУБД!)
ALTER TABLE pii_token_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE pii_token_vault FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_citizen_session_isolation ON pii_token_vault;
CREATE POLICY rls_citizen_session_isolation ON pii_token_vault
    USING (citizen_session_id = current_setting('app.current_citizen_session_id', true));

-- 2. Реестр проверенных межведомственных конвертов СМЭВ 3.0 и обращений 59-ФЗ (без открытых ПДн!)
CREATE TABLE IF NOT EXISTS smev3_processed_envelopes (
    message_id VARCHAR(64) PRIMARY KEY,
    citizen_session_id VARCHAR(128) NOT NULL,
    sender_mnemonic VARCHAR(32) NOT NULL,
    service_code VARCHAR(64) NOT NULL,
    pii_tokens_replaced INTEGER NOT NULL DEFAULT 0,
    shield_stage_triggered VARCHAR(32) NOT NULL DEFAULT 'NONE',
    shield_risk_score NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
    processed_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Неизменяемый криптографический журнал событий безопасности по ГОСТ Р 59548-2022 и ГОСТ Р 34.11-2012 (Стрибог-256)
CREATE TABLE IF NOT EXISTS fstec_security_audit_log (
    seq_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(128) NOT NULL,
    citizen_session_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(96) NOT NULL,
    fstec_measure VARCHAR(64) NOT NULL DEFAULT 'РСБ.1 / ГОСТ Р 59548-2022',
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'HIGH', 'CRITICAL')),
    payload_summary JSONB NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    streebog256_hash CHAR(64) NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_fstec_audit_event_severity
    ON fstec_security_audit_log (event_type, severity, occurred_at DESC);

-- Триггерная функция запрета любых операций UPDATE, DELETE и TRUNCATE над журналом аудита ИБ
CREATE OR REPLACE FUNCTION forbid_fstec_audit_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'CRITICAL ГОСТ Р 59548-2022 VIOLATION: Модификация или удаление записей журнала fstec_security_audit_log строго запрещены (операция %)!', TG_OP
        USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS trg_immutable_fstec_audit_log ON fstec_security_audit_log;
CREATE TRIGGER trg_immutable_fstec_audit_log
    BEFORE UPDATE OR DELETE OR TRUNCATE ON fstec_security_audit_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION forbid_fstec_audit_log_mutation();

COMMIT;

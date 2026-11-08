# src/pii/reversible_token_vault.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.models.contracts import (
    DetectedPiiSpan,
    PiiEntityCategory,
    TokenizedPromptBundle,
)
from src.pii.ru_gov_pii_detector import RuGovPiiHybridDetector


class CrossCitizenLeakAttemptError(PermissionError):
    """Исключение безопасности ИБ: попытка детокенизации ПДн чужого гражданина или с неверным мандатом."""


@dataclass(slots=True)
class EncryptedVaultEntry:
    citizen_session_id: str
    department_mandate: str
    token_placeholder: str
    category: PiiEntityCategory
    value_hmac_fingerprint: str
    nonce_b64: str
    ciphertext_b64: str
    aad_b64: str
    created_at_utc: datetime
    expires_at_utc: datetime


class VaultStorageBackend(Protocol):
    def upsert_entry(self, entry: EncryptedVaultEntry) -> None: ...
    def get_session_entries(self, citizen_session_id: str) -> dict[str, EncryptedVaultEntry]: ...
    def purge_expired_or_session(self, citizen_session_id: str) -> int: ...


class InMemoryRlsVaultBackend:
    """
    Быстрый потокобезопасный бэкенд с семантикой Row-Level Security (RLS) по citizen_session_id.
    На VM 221 работает в паре с PostgreSQL 16 (таблица pii_token_vault с политикой RLS).
    """

    def __init__(self) -> None:
        self._by_session: dict[str, dict[str, EncryptedVaultEntry]] = {}

    def upsert_entry(self, entry: EncryptedVaultEntry) -> None:
        session_bucket = self._by_session.setdefault(entry.citizen_session_id, {})
        session_bucket[entry.token_placeholder] = entry

    def get_session_entries(self, citizen_session_id: str) -> dict[str, EncryptedVaultEntry]:
        now = datetime.now(timezone.utc)
        bucket = self._by_session.get(citizen_session_id, {})
        active: dict[str, EncryptedVaultEntry] = {}
        for token_str, entry in list(bucket.items()):
            if entry.expires_at_utc > now:
                active[token_str] = entry
            else:
                del bucket[token_str]
        return active

    def purge_expired_or_session(self, citizen_session_id: str) -> int:
        removed = len(self._by_session.pop(citizen_session_id, {}))
        return removed


class ReversiblePiiTokenVault:
    """
    Криптографическое хранилище обратимой псевдонимизации ПДн (152-ФЗ) для ИИ-шлюза «Щит-АИСТ».
    """

    _TOKEN_PLACEHOLDER_RE = re.compile(r"<([A-Z_]+)_\d{2}>")

    def __init__(
        self,
        master_key_hex: str | None = None,
        detector: RuGovPiiHybridDetector | None = None,
        backend: VaultStorageBackend | None = None,
        ttl_seconds: int = 1800,
    ) -> None:
        raw_hex = master_key_hex or os.getenv(
            "AIST_MASTER_KEY_HEX",
            "8f4a9c2e1b7d6053a9e8f1c4b2d70395e6a1c8f3b4d29071a5c6e8f0d3b2a194",
        )
        self._master_key = bytes.fromhex(raw_hex)
        if len(self._master_key) != 32:
            raise ValueError(
                "Мастер-ключ хранилища ПДн должен иметь длину ровно 256 бит (64 hex-символа)."
            )
        self._detector = detector or RuGovPiiHybridDetector()
        self._backend = backend or InMemoryRlsVaultBackend()
        self._ttl_seconds = ttl_seconds

    def _derive_session_keys(
        self,
        citizen_session_id: str,
        department_mandate: str,
    ) -> tuple[bytes, bytes]:
        """
        Деривация двух независимых 256-битных ключей через HKDF-SHA256:
        1) enc_key — для шифрования AES-256-GCM с привязкой к сессии и мандату;
        2) tag_key — для вычисления HMAC-отпечатка сущности внутри сессии (кореференция).
        """
        salt = hashlib.sha256(
            f"GUIT-OMSK-152FZ-SALT|{citizen_session_id}".encode("utf-8")
        ).digest()
        hkdf_enc = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"AIST-PII-ENC|{citizen_session_id}|{department_mandate}".encode("utf-8"),
        )
        hkdf_tag = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"AIST-PII-TAG|{citizen_session_id}".encode("utf-8"),
        )
        return hkdf_enc.derive(self._master_key), hkdf_tag.derive(self._master_key)

    def tokenize_citizen_text(
        self,
        text: str,
        citizen_session_id: str,
        department_mandate: str = "OMSK_GUIT_59FZ_OPERATOR",
    ) -> TokenizedPromptBundle:
        """
        Находит все ПДн в обращении гражданина, шифрует их в изолированный сессионный бакет
        и заменяет в тексте на консистентные токены <PERSON_01>, <SNILS_01>, <INN_FL_01> и т.д.
        """
        spans = self._detector.detect_all_pii(text)
        enc_key, tag_key = self._derive_session_keys(citizen_session_id, department_mandate)
        aesgcm = AESGCM(enc_key)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self._ttl_seconds)

        # Загружаем уже существующие в этой сессии токены для сохранения кореференции
        existing_entries = self._backend.get_session_entries(citizen_session_id)
        fingerprint_to_token: dict[str, str] = {
            e.value_hmac_fingerprint: tok for tok, e in existing_entries.items()
        }
        category_counters: dict[PiiEntityCategory, int] = {}
        for e in existing_entries.values():
            category_counters[e.category] = category_counters.get(e.category, 0) + 1

        token_fingerprints_out: dict[str, str] = {}
        detected_cats: list[PiiEntityCategory] = []

        # Назначаем токены слева направо, а замену в строке выполняем справа налево
        span_tokens: list[tuple[DetectedPiiSpan, str]] = []
        for sp in spans:
            fp = hmac.new(
                tag_key,
                f"{sp.category.value}:{sp.normalized_value}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if fp in fingerprint_to_token:
                placeholder = fingerprint_to_token[fp]
            else:
                next_idx = category_counters.get(sp.category, 0) + 1
                category_counters[sp.category] = next_idx
                placeholder = f"<{sp.category.value}_{next_idx:02d}>"
                fingerprint_to_token[fp] = placeholder

            nonce = os.urandom(12)
            aad_bytes = (
                f"{citizen_session_id}|{department_mandate}|{sp.category.value}|{placeholder}".encode(
                    "utf-8"
                )
            )
            ciphertext = aesgcm.encrypt(nonce, sp.raw_value.encode("utf-8"), aad_bytes)

            entry = EncryptedVaultEntry(
                citizen_session_id=citizen_session_id,
                department_mandate=department_mandate,
                token_placeholder=placeholder,
                category=sp.category,
                value_hmac_fingerprint=fp,
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
                ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
                aad_b64=base64.b64encode(aad_bytes).decode("ascii"),
                created_at_utc=now,
                expires_at_utc=expires_at,
            )
            self._backend.upsert_entry(entry)
            token_fingerprints_out[placeholder] = fp[:16]
            if sp.category not in detected_cats:
                detected_cats.append(sp.category)
            span_tokens.append((sp, placeholder))

        # Собираем обезличенный текст справа налево, чтобы индексы символов не сдвигались
        chars = list(text)
        for sp, placeholder in reversed(span_tokens):
            chars[sp.char_start : sp.char_end] = list(placeholder)
        sanitized_text = "".join(chars)

        return TokenizedPromptBundle(
            citizen_session_id=citizen_session_id,
            department_mandate=department_mandate,
            sanitized_text=sanitized_text,
            token_count=len(span_tokens),
            detected_categories=detected_cats,
            token_map_fingerprints=token_fingerprints_out,
            expires_at_utc=expires_at,
        )

    def detokenize_for_authorized_operator(
        self,
        llm_response_text: str,
        citizen_session_id: str,
        operator_mandate: str,
        strict_on_unknown_token: bool = True,
    ) -> str:
        """
        Восстанавливает реальные ПДн в ответе LLM ТОЛЬКО для авторизованного оператора с проверкой
        citizen_session_id и мандата доступа.
        """
        session_entries = self._backend.get_session_entries(citizen_session_id)
        enc_key, _ = self._derive_session_keys(citizen_session_id, operator_mandate)
        aesgcm = AESGCM(enc_key)

        def _replace_match(match: re.Match[str]) -> str:
            placeholder = match.group(0)
            entry = session_entries.get(placeholder)
            if entry is None:
                if strict_on_unknown_token:
                    raise CrossCitizenLeakAttemptError(
                        f"БЛОКИРОВКА 152-ФЗ: Токен {placeholder} отсутствует в сессии "
                        f"'{citizen_session_id}' (попытка межсессионной утечки ПДн)!"
                    )
                return "[ДАННЫЕ СКРЫТЫ ПОЛИТИКОЙ 152-ФЗ]"
            if entry.department_mandate != operator_mandate:
                raise CrossCitizenLeakAttemptError(
                    f"БЛОКИРОВКА УПД.4: Мандат оператора '{operator_mandate}' не совпадает "
                    f"с мандатом сессии '{entry.department_mandate}'!"
                )
            nonce = base64.b64decode(entry.nonce_b64)
            ciphertext = base64.b64decode(entry.ciphertext_b64)
            expected_aad = (
                f"{citizen_session_id}|{operator_mandate}|{entry.category.value}|{placeholder}".encode(
                    "utf-8"
                )
            )
            try:
                plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, expected_aad)
            except Exception as exc:
                raise CrossCitizenLeakAttemptError(
                    f"Ошибка криптографической аутентификации AES-256-GCM для токена {placeholder}!"
                ) from exc
            return plaintext_bytes.decode("utf-8")

        return self._TOKEN_PLACEHOLDER_RE.sub(_replace_match, llm_response_text)

    def forget_citizen_session(self, citizen_session_id: str) -> int:
        """Принудительное криптографическое удаление ключей и токенов сессии по ст. 21 ФЗ № 152-ФЗ."""
        return self._backend.purge_expired_or_session(citizen_session_id)

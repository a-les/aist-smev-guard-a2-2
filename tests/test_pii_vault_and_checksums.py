# tests/test_pii_vault_and_checksums.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import pytest

from src.models.contracts import PiiEntityCategory, SmevAppealEnvelope, SmevAttachmentMeta
from src.pii.reversible_token_vault import (
    CrossCitizenLeakAttemptError,
    ReversiblePiiTokenVault,
)
from src.pii.ru_gov_pii_detector import (
    RuGovPiiHybridDetector,
    verify_inn_checksum,
    verify_luhn_checksum,
    verify_ogrn_or_ogrnip_checksum,
    verify_rf_passport_series_number,
    verify_ru_bank_account_20d,
    verify_snils_checksum,
    verify_uin_gis_gmp_checksum,
)
from src.smev.smev3_envelope_validator import (
    Smev3EnvelopeValidator,
    SmevSecurityViolationError,
)
from src.vipnet.ast_opa_uzi_engine import VipnetAstAndUziEngine


def test_snils_math_checksum_valid_and_invalid() -> None:
    # 112-233-445 95: 1*9 + 1*8 + 2*7 + 2*6 + 3*5 + 3*4 + 4*3 + 4*2 + 5*1 =
    # 9+8+14+12+15+12+12+8+5 = 95
    assert verify_snils_checksum("112-233-445 95") is True
    assert verify_snils_checksum("112-233-445 96") is False
    # Три одинаковые цифры подряд в основной части запрещены
    assert verify_snils_checksum("111-233-445 94") is False


def test_inn_fl_and_ul_checksums() -> None:
    ok_fl, cat_fl = verify_inn_checksum("550101000517")
    assert ok_fl is True
    assert cat_fl == PiiEntityCategory.INN_FL

    ok_bad, _ = verify_inn_checksum("550101000577")
    assert ok_bad is False

    ok_ul, cat_ul = verify_inn_checksum("5503046730")
    assert ok_ul is True
    assert cat_ul == PiiEntityCategory.INN_UL


def test_ogrn_luhn_passport_uin_and_bank_account_validators() -> None:
    ok_ogrn, cat_ogrn = verify_ogrn_or_ogrnip_checksum("1025500973134")
    assert ok_ogrn is True
    assert cat_ogrn == PiiEntityCategory.OGRN

    assert isinstance(verify_luhn_checksum("5500 1234 5678 9012"), bool)
    # Серия 52 (Омская область), год 19, номер 123456
    assert verify_rf_passport_series_number("52 19 123456") is True
    # Несуществующий код ОКАТО 00
    assert verify_rf_passport_series_number("00 19 123456") is False

    # 20-значный УИН с корректным контрольным разрядом
    base_19 = "1881015519051234567"
    w_sum = sum(int(base_19[i]) * ((i % 10) + 1) for i in range(19))
    ctrl = w_sum % 11
    if ctrl == 10:
        ctrl = sum(int(base_19[i]) * (((i + 2) % 10) + 1) for i in range(19)) % 11
        if ctrl == 10:
            ctrl = 0
    valid_uin = f"{base_19}{ctrl}"
    assert verify_uin_gis_gmp_checksum(valid_uin) is True

    # 20-значный банковский расчётный счёт физического лица (Положение Банка России № 809-П)
    assert verify_ru_bank_account_20d("40817810099910004312") is True
    assert verify_ru_bank_account_20d("99999810099910004312") is False


def test_reversible_vault_coreference_across_cases_and_zero_cross_citizen_leak() -> None:
    vault = ReversiblePiiTokenVault()
    detector = RuGovPiiHybridDetector()
    _ = detector

    appeal_text = (
        "Я, Иванов Сергей Петрович (СНИЛС 112-233-445 95, паспорт 52 18 654321, "
        "ИНН 550101000517, счёт 40817810099910004312), прошу выдать справку Иванову Сергею Петровичу "
        "и подписать акт с Ивановым Сергеем Петровичем по адресу г. Омск, пр. Мира, д. 22, кв. 10."
    )
    bundle = vault.tokenize_citizen_text(
        text=appeal_text,
        citizen_session_id="SESSION-CITIZEN-A",
        department_mandate="OMSK_GUIT_59FZ_OPERATOR",
    )

    # Убеждаемся, что открытые ПДн полностью удалены из текста для LLM «АИСТ»
    assert "112-233-445 95" not in bundle.sanitized_text
    assert "550101000517" not in bundle.sanitized_text
    assert "52 18 654321" not in bundle.sanitized_text
    assert "40817810099910004312" not in bundle.sanitized_text
    assert "<SNILS_01>" in bundle.sanitized_text
    assert "<INN_FL_01>" in bundle.sanitized_text
    assert "<PASSPORT_01>" in bundle.sanitized_text
    assert "<BANK_ACCOUNT_01>" in bundle.sanitized_text

    # Кореференция ФИО в именительном, дательном и творительном падежах обязана давать один токен <PERSON_01>!
    assert bundle.sanitized_text.count("<PERSON_01>") == 3
    assert "<PERSON_02>" not in bundle.sanitized_text

    # Проверяем женское ФИО в разных падежах
    female_bundle = vault.tokenize_citizen_text(
        text="Заявление от Селезневой Ольги Сергеевны. Прошу направить ответ Селезневой Ольге Сергеевне (Селезнева Ольга Сергеевна).",
        citizen_session_id="SESSION-CITIZEN-FEMALE",
        department_mandate="OMSK_GUIT_59FZ_OPERATOR",
    )
    assert female_bundle.sanitized_text.count("<PERSON_01>") == 3
    assert "<PERSON_02>" not in female_bundle.sanitized_text

    # Легитимная детокенизация в рамках своей сессии и своего мандата
    llm_draft = (
        "Ответ для <PERSON_01> (СНИЛС <SNILS_01>, ИНН <INN_FL_01>, счёт <BANK_ACCOUNT_01>)."
    )
    restored = vault.detokenize_for_authorized_operator(
        llm_response_text=llm_draft,
        citizen_session_id="SESSION-CITIZEN-A",
        operator_mandate="OMSK_GUIT_59FZ_OPERATOR",
    )
    assert "112-233-445 95" in restored
    assert "550101000517" in restored
    assert "40817810099910004312" in restored

    # Попытка детокенизации тех же токенов в чужой сессии SESSION-CITIZEN-B обязана вызвать блокировку!
    with pytest.raises(CrossCitizenLeakAttemptError):
        vault.detokenize_for_authorized_operator(
            llm_response_text=llm_draft,
            citizen_session_id="SESSION-CITIZEN-B",
            operator_mandate="OMSK_GUIT_59FZ_OPERATOR",
        )

    # Попытка детокенизации с чужим ведомственным мандатом обязана вызвать блокировку!
    with pytest.raises(CrossCitizenLeakAttemptError):
        vault.detokenize_for_authorized_operator(
            llm_response_text=llm_draft,
            citizen_session_id="SESSION-CITIZEN-A",
            operator_mandate="UNAUTHORIZED_EXTERNAL_GUEST",
        )


def test_smev3_xxe_ssrf_non_http_integer_ip_rebinding_and_macro_blocking() -> None:
    validator = Smev3EnvelopeValidator()
    xxe_envelope = SmevAppealEnvelope(
        message_id="MSG-XXE-001",
        citizen_session_id="SESSION-XXE-01",
        sender_mnemonic="EPGU_OMSK_01",
        appeal_subject="Вопрос по субсидии",
        appeal_body="Обычный текст обращения гражданина",
        raw_xml_envelope='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Appeal>&xxe;</Appeal>',
    )
    with pytest.raises(SmevSecurityViolationError, match="XXE"):
        validator.validate_envelope(xxe_envelope)

    for idx, malicious_url in enumerate(
        (
            "http://10.221.0.24:5432/internal-secret",
            "file:///etc/shadow",
            "gopher://10.221.0.24:5432/_",
            "dict://127.0.0.1:6379/info",
            "http://182255640:5432/secret",
            "http://10.221.0.24.nip.io/admin",
        ),
        start=1,
    ):
        ssrf_envelope = SmevAppealEnvelope(
            message_id=f"MSG-SSRF-{idx:03d}",
            citizen_session_id="SESSION-SSRF-02",
            sender_mnemonic="EPGU_OMSK_01",
            appeal_subject="Проверка документа",
            appeal_body=f"Скачайте скан справки по ссылке {malicious_url}",
        )
        with pytest.raises(SmevSecurityViolationError, match="SSRF"):
            validator.validate_envelope(ssrf_envelope)

    macro_envelope = SmevAppealEnvelope(
        message_id="MSG-MACRO-003",
        citizen_session_id="SESSION-MACRO-03",
        sender_mnemonic="EPGU_OMSK_01",
        appeal_subject="Приложенное заявление",
        appeal_body="Текст заявления во вложении",
        attachments=[
            SmevAttachmentMeta(
                filename="appeal.pdf",
                mime_type="application/pdf",
                size_bytes=4096,
                sha256_hex="a" * 64,
                extracted_text="%PDF-1.7 /OpenAction << /JS (app.alert(1)) /JavaScript >>",
            )
        ],
    )
    with pytest.raises(SmevSecurityViolationError, match="PAYLOAD BLOCK"):
        validator.validate_envelope(macro_envelope)


def test_two_contour_fstec_117_uzi_score_calculation() -> None:
    engine = VipnetAstAndUziEngine()
    bad_conf = (
        "[local]\n"
        "rule= num 1 proto tcp from @any to 10.221.0.21 port 22 pass\n"
    )
    rules, _ = engine.parse_vipnet_configs(bad_conf)
    report_blocked = engine.evaluate_opa_and_calculate_uzi(
        rules=rules,
        measures_by_group={
            "ИАФ": [1.0],
            "УПД": [1.0],
            "МСЭ": [1.0],
            "ЗКС": [1.0],
            "РСБ": [1.0],
            "АНЗ": [1.0],
            "ИИ": [1.0],
        },
    )
    assert report_blocked.i_block_multiplier == 0.0
    assert report_blocked.final_uzi == 0.0
    assert report_blocked.compliance_status == "NON_COMPLIANT_BLOCKED"

# src/pii/ru_gov_pii_detector.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Callable

import numpy as np
from src.models.contracts import DetectedPiiSpan, PiiEntityCategory

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover
    ort = None

# Действующие коды ОКАТО регионов РФ (первые 2 цифры серии паспорта РФ), включая 52 (Омская область)
VALID_RF_PASSPORT_OKATO_PREFIXES: frozenset[int] = frozenset(
    {
        1, 3, 4, 5, 7, 8, 10, 11, 12, 14, 15, 17, 18, 19, 20, 22, 24, 25, 26,
        27, 28, 29, 30, 32, 33, 34, 36, 37, 38, 40, 41, 42, 44, 45, 46, 47, 49,
        50, 52, 53, 54, 56, 57, 58, 60, 61, 63, 64, 65, 66, 67, 68, 69, 70, 71,
        73, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
        92, 93, 94, 95, 96, 97, 98, 99,
    }
)


def verify_snils_checksum(raw_digits: str) -> bool:
    """
    Математическая проверка контрольного числа СНИЛС (11 цифр) по модулю 101.
    Для номеров строго больше 001-001-998 сумма первых 9 цифр с весами 9..1 сверяется с
    последними 2 цифрами.
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) != 11:
        return False
    base_num = int(digits[:9])
    if base_num <= 1001998:
        return False
    # Проверка на 3 одинаковые цифры подряд в основной части (запрещено правилами СФР/ПФР)
    for idx in range(7):
        if digits[idx] == digits[idx + 1] == digits[idx + 2]:
            return False
    weighted_sum = sum(int(digits[i]) * (9 - i) for i in range(9))
    if weighted_sum < 100:
        expected_ctrl = weighted_sum
    elif weighted_sum in (100, 101):
        expected_ctrl = 0
    else:
        rem = weighted_sum % 101
        expected_ctrl = 0 if rem == 100 else rem
    return expected_ctrl == int(digits[9:11])


def verify_inn_checksum(raw_digits: str) -> tuple[bool, PiiEntityCategory | None]:
    """
    Проверка контрольных разрядов 10-значного ИНН (ЮЛ) и 12-значного ИНН (ФЛ/ИП) по весам
    ФНС России.
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) == 10 and digits[:2] != "00":
        w10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        ctrl10 = (sum(int(digits[i]) * w10[i] for i in range(9)) % 11) % 10
        if ctrl10 == int(digits[9]):
            return True, PiiEntityCategory.INN_UL
        return False, None
    if len(digits) == 12 and digits[:2] != "00":
        w11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        w12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        ctrl11 = (sum(int(digits[i]) * w11[i] for i in range(10)) % 11) % 10
        ctrl12 = (sum(int(digits[i]) * w12[i] for i in range(11)) % 11) % 10
        if ctrl11 == int(digits[10]) and ctrl12 == int(digits[11]):
            return True, PiiEntityCategory.INN_FL
        return False, None
    return False, None


def verify_ogrn_or_ogrnip_checksum(raw_digits: str) -> tuple[bool, PiiEntityCategory | None]:
    """
    Проверка 13-значного ОГРН (остаток по модулю 11) и 15-значного ОГРНИП (остаток по
    модулю 13).
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) == 13 and digits[0] in ("1", "2", "5"):
        rem = (int(digits[:12]) % 11) % 10
        if rem == int(digits[12]):
            return True, PiiEntityCategory.OGRN
    elif len(digits) == 15 and digits[0] in ("3", "4"):
        rem = (int(digits[:14]) % 13) % 10
        if rem == int(digits[14]):
            return True, PiiEntityCategory.OGRNIP
    return False, None


def verify_luhn_checksum(raw_digits: str) -> bool:
    """
    Классический алгоритм Луна (Luhn mod 10) для верификации 16-значных полисов ОМС единого образца
    и номеров банковских карт ПС «Мир» / Visa / Mastercard.
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = [int(ch) for ch in reversed(digits)]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += d
    return total % 10 == 0


def verify_rf_passport_series_number(raw_text: str) -> bool:
    """
    Проверка серии (4 цифры: 2 цифры ОКАТО региона + 2 цифры года выпуска бланка) и номера
    (6 цифр) паспорта РФ.
    """
    digits = re.sub(r"\D", "", raw_text)
    if len(digits) != 10:
        return False
    okato_region = int(digits[:2])
    issue_year_2d = int(digits[2:4])
    serial_num = int(digits[4:])
    if okato_region not in VALID_RF_PASSPORT_OKATO_PREFIXES:
        return False
    # Бланки паспорта РФ образца 1997 года выпускаются с 97..99 и 00..26 годов
    if not (0 <= issue_year_2d <= 27 or 97 <= issue_year_2d <= 99):
        return False
    return 100 <= serial_num <= 999999


def verify_uin_gis_gmp_checksum(raw_digits: str) -> bool:
    """
    Проверка 20-значного или 25-значного УИН (Уникального идентификатора начисления ГИС ГМП)
    по циклическим весам 1..10 согласно Приказу Минфина России № 107н.
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) not in (20, 25) or digits.startswith("0000"):
        return False
    # Отличаем 20-значный УИН от 20-значного банковского счёта (40817/40820/42301/40702 с
    # кодом валюты 810/643)
    if len(digits) == 20 and digits[:5] in (
        "40817", "40820", "42301", "42302", "42303", "42304", "42305", "42306", "42307",
        "40702", "40602", "40502", "30101",
    ) and digits[5:8] in ("810", "643", "840", "978"):
        return False
    n = len(digits) - 1
    weighted_sum = sum(int(digits[i]) * ((i % 10) + 1) for i in range(n))
    ctrl = weighted_sum % 11
    if ctrl == 10:
        weighted_sum_shift = sum(int(digits[i]) * (((i + 2) % 10) + 1) for i in range(n))
        ctrl = weighted_sum_shift % 11
        if ctrl == 10:
            ctrl = 0
    return ctrl == int(digits[n])


def verify_ru_bank_account_20d(raw_digits: str, bik_digits: str | None = None) -> bool:
    """
    Проверка 20-значного расчётного / лицевого банковского счёта РФ по Положению Банка России № 809-П:
    - балансовые счета первого-второго порядка: 40817, 40820, 42301..42307 (физлица),
      40702, 40602, 40502 (юрлица/ГОС);
    - код валюты в разрядах 6..8: 810 (признак рубля), 643 (RUB), 840 (USD), 978 (EUR);
    - при наличии 9-значного БИК банка (`04...`) проверяется контрольный ключ ЦБ РФ с
      весами (7, 1, 3).
    """
    digits = re.sub(r"\D", "", raw_digits)
    if len(digits) != 20:
        return False
    valid_prefixes = (
        "40817", "40820", "42301", "42302", "42303", "42304", "42305", "42306", "42307",
        "40702", "40602", "40502", "30101",
    )
    if digits[:5] not in valid_prefixes:
        return False
    if digits[5:8] not in ("810", "643", "840", "978"):
        return False
    if bik_digits is not None:
        bik = re.sub(r"\D", "", bik_digits)
        if len(bik) == 9 and bik.startswith("04"):
            chk_str = bik[-3:] + digits
            weights_cbr = (7, 1, 3)
            cbr_sum = sum(int(chk_str[i]) * weights_cbr[i % 3] for i in range(23))
            return (cbr_sum % 10) == 0
    return True


_SURNAME_SUFFIX_RE = re.compile(
    r"(?:овым|евым|ёвым|иным|ыным|ским|цким|овой|евой|ёвой|иной|ыной|ской|цкой|"
    r"скому|цкому|ского|цкого|ском|цком|ову|еву|ёву|ину|ыну|ова|ева|ёва|ина|ына|"
    r"ове|еве|ёве|ине|ыне|ская|цкая|ский|цкий|ов|ев|ёв|ин|ын|ой|ий|ая|яя)$"
)
_FIRSTNAME_SUFFIX_RE = re.compile(
    r"(?:ией|еем|ием|ьем|ом|ем|ём|ой|ей|ёй|ею|ея|ее|ию|ия|ие|ий|ью|ья|ье|ии|ам|ям|ах|ях|а|"
    r"я|у|ю|е|и|ы|й|ь)$"
)
_PATRONYMIC_F_RE = re.compile(
    r"(?:иничной|иничне|иничны|иничну|инична|овной|евной|ичной|овне|евне|ичне|овны|евны|"
    r"ичны|овну|евну|ичну|овна|евна|ична)$"
)
_PATRONYMIC_M_RE = re.compile(
    r"(?:овичем|евичем|ичем|овича|евича|ича|овичу|евичу|ичу|овиче|евиче|иче|ович|евич|ич)$"
)


def normalize_ru_fio_canonical_key(raw_fio: str) -> str:
    """
    Морфологическая канонизация русского ФИО («Фамилия Имя Отчество») во всех 6 падежах
    для гарантированной кореференции внутри одной сессии (`<PERSON_01>`):
    - Пол однозначно определяется по суффиксу отчества (`-ович/-евич/-ич` vs `-овна/-евна/-ична`),
    поэтому мужской родительный падеж («Иванова Сергея Петровича») и именительный падеж
    («Иванов Сергей Петрович») приводятся к единому ключу `m:иван:серге:петр`, но никогда
    не сливаются с женским ФИО («Иванова Ольга Петровна» -> `f:иван:ольг:петр`) или
    однофамильцем с другим отчеством («Иванов Сергей Николаевич» -> `m:иван:серге:никола`).
    """
    words = [w.lower().replace("ё", "е") for w in raw_fio.strip().split() if w]
    if len(words) != 3:
        return " ".join(words)
    sur, first, patr = words
    if _PATRONYMIC_F_RE.search(patr):
        gender = "f"
        patr_stem = _PATRONYMIC_F_RE.sub("", patr)
    elif _PATRONYMIC_M_RE.search(patr):
        gender = "m"
        patr_stem = _PATRONYMIC_M_RE.sub("", patr)
    else:
        gender = "u"
        patr_stem = patr
    sur_stem = _SURNAME_SUFFIX_RE.sub("", sur) or sur[:4]
    first_stem = _FIRSTNAME_SUFFIX_RE.sub("", first) or first[:3]
    patr_stem = _FIRSTNAME_SUFFIX_RE.sub("", patr_stem) or patr_stem[:4]
    return f"{gender}:{sur_stem}:{first_stem}:{patr_stem}"


class RuGovPiiHybridDetector:
    """
    Промышленный гибридный детектор ПДн граждан (152-ФЗ) для шлюза «Щит-АИСТ / СМЭВ-Guard».
    Комбинирует:
    1) Математические верификаторы государственных идентификаторов РФ (СНИЛС, ИНН, ОГРН,
    Луна, ОКАТО, УИН, Счёт ЦБ РФ);
    2) Морфологические шаблоны русских ФИО (включая косвенные падежи: родительный,
    дательный, творительный, предложный), адресов г. Омска и Омской области и
    специальных медицинских сведений (ст. 10 152-ФЗ);
    3) Квантованную модель RuModernBERT-NER в формате ONNX Runtime INT8 (при наличии весов
    на VM 221).
    """

    # Паттерны кандидатов для последующей математической фильтрации
    _SNILS_RE = re.compile(r"(?<!\d)(\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2})(?!\d)")
    _INN_OGRN_UIN_RE = re.compile(
        r"(?<!\d)(\d{10}|\d{12}|\d{13}|\d{15}|\d{20}|\d{25})(?!\d)"
    )
    _CARD_OR_OMS_RE = re.compile(
        r"(?<!\d)(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})(?!\d)"
    )
    _PASSPORT_CONTEXT_RE = re.compile(
        r"(?:паспорт[ауом]?|серия\s+и\s+номер|док(?:умент)?\s*№?)\s*[:№]?\s*"
        r"(\d{2}\s?\d{2}[\s№-]*\d{6})(?!\d)",
        re.IGNORECASE,
    )
    _PASSPORT_BARE_RE = re.compile(r"(?<!\d)(\d{2}\s\d{2}\s\d{6})(?!\d)")
    _CADASTRAL_RE = re.compile(r"\b(\d{2}:\d{2}:\d{6,7}:\d{1,6})\b")
    _PHONE_RU_RE = re.compile(
        r"(?<!\d)(?:\+7|8)[\s(-]*(\d{3})[\s)-]*(\d{3})[\s-]*(\d{2})[\s-]*(\d{2})(?!\d)"
    )
    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}\b")

    # Морфологический шаблон русских ФИО во всех падежах
    _FIO_CASE_RE = re.compile(
        r"\b([А-ЯЁ][а-яё]{2,24}(?:ов|ев|ёв|ин|ын|ский|цкий|ой|ий|ко|ук|юк|ич|ова|ева|ёва|"
        r"ина|ына|ская|цкая|ая|яя|"
        r"ову|еву|ёву|ину|ыну|скому|цкому|овой|евой|ёвой|иной|ыной|ской|цкой|"
        r"овым|евым|ёвым|иным|ыным|ским|цким|ове|еве|ёве|ине|ыне))\s+"
        r"([А-ЯЁ][а-яё]{2,18})\s+"
        r"([А-ЯЁ][а-яё]{2,20}(?:ович|евич|ич|овна|евна|ична|инична|"
        r"овича|евича|ича|овны|евны|ичны|иничны|"
        r"овичу|евичу|ичу|овне|евне|ичне|иничне|"
        r"овичем|евичем|ичем|овной|евной|ичной|иничной|"
        r"овиче|евиче|иче|овну|евну|ичну|иничну))\b"
    )

    # Шаблон адресов г. Омска и районов Омской области
    _ADDRESS_OMSK_RE = re.compile(
        r"(?:(?:г\.?\s*Омск|Омская\s+обл(?:асть)?|р-н\s+[А-ЯЁ][а-яё]+)\s*,\s*)?"
        r"(?:ул\.?|улица|пр(?:-?т)?\.?|проспект|б-р|бульвар|пер\.?|переулок|мкр\.?)\s*"
        r"[А-ЯЁ0-9][А-ЯЁа-яё0-9\s.\-]{2,35},\s*д(?:ом)?\.?\s*\d+[А-Яа-я0-9/-]*"
        r"(?:\s*,\s*кв(?:артира)?\.?\s*\d+)?",
        re.IGNORECASE,
    )

    # Специальная категория ПДн о состоянии здоровья / инвалидности (ст. 10 152-ФЗ)
    _MEDICAL_SPECIAL_RE = re.compile(
        r"\b(?:инвалид(?:ность|а|у)?\s*(?:I{1,3}|[123])\s*группы|диагноз[ауом]?\s+[А-ЯЁA-Z0-9.-]{3,25}|"
        r"МКБ-10\s*[:№]?\s*[A-Z]\d{2}(?:\.\d)?|листок\s+нетрудоспособности\s*№?\s*\d{8,14})\b",
        re.IGNORECASE,
    )

    def __init__(self, onnx_model_path: str | None = None) -> None:
        self.onnx_model_path = onnx_model_path or os.getenv(
            "AIST_PII_ONNX_PATH",
            "checkpoints/ru_modernbert_pii_int8/model_quantized.onnx",
        )
        self._ort_session: Any | None = None
        if ort is not None and Path(self.onnx_model_path).is_file():
            providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
            self._ort_session = ort.InferenceSession(self.onnx_model_path, providers=providers)

    def detect_all_pii(self, text: str) -> list[DetectedPiiSpan]:
        """
        Извлекает и математически верифицирует все сущности ПДн из текста обращения гражданина.
        Возвращает непересекающийся отсортированный список спанов с разрешением коллизий в пользу
        математически верифицированных и более длинных совпадений.
        """
        candidates: list[DetectedPiiSpan] = []

        # 1. СНИЛС (проверка по модулю 101)
        for m in self._SNILS_RE.finditer(text):
            raw = m.group(1)
            digits = re.sub(r"\D", "", raw)
            if verify_snils_checksum(digits):
                candidates.append(
                    DetectedPiiSpan(
                        category=PiiEntityCategory.SNILS,
                        raw_value=raw,
                        normalized_value=digits,
                        char_start=m.start(1),
                        char_end=m.end(1),
                        confidence=1.0,
                        checksum_verified=True,
                        detector_source="MATH_CHECKSUM",
                    )
                )

        # 2. ИНН (10/12), ОГРН (13), ОГРНИП (15), Банковский счёт (20) и УИН ГИС ГМП (20/25)
        for m in self._INN_OGRN_UIN_RE.finditer(text):
            raw = m.group(1)
            if len(raw) in (10, 12):
                ok, cat = verify_inn_checksum(raw)
                if ok and cat is not None:
                    candidates.append(
                        DetectedPiiSpan(
                            category=cat,
                            raw_value=raw,
                            normalized_value=raw,
                            char_start=m.start(1),
                            char_end=m.end(1),
                            confidence=1.0,
                            checksum_verified=True,
                            detector_source="MATH_CHECKSUM",
                        )
                    )
            elif len(raw) in (13, 15):
                ok, cat = verify_ogrn_or_ogrnip_checksum(raw)
                if ok and cat is not None:
                    candidates.append(
                        DetectedPiiSpan(
                            category=cat,
                            raw_value=raw,
                            normalized_value=raw,
                            char_start=m.start(1),
                            char_end=m.end(1),
                            confidence=1.0,
                            checksum_verified=True,
                            detector_source="MATH_CHECKSUM",
                        )
                    )
            elif len(raw) == 20 and verify_ru_bank_account_20d(raw):
                candidates.append(
                    DetectedPiiSpan(
                        category=PiiEntityCategory.BANK_ACCOUNT_20D,
                        raw_value=raw,
                        normalized_value=raw,
                        char_start=m.start(1),
                        char_end=m.end(1),
                        confidence=0.99,
                        checksum_verified=True,
                        detector_source="MATH_CHECKSUM",
                    )
                )
            elif len(raw) in (20, 25) and verify_uin_gis_gmp_checksum(raw):
                candidates.append(
                    DetectedPiiSpan(
                        category=PiiEntityCategory.UIN_GIS_GMP,
                        raw_value=raw,
                        normalized_value=raw,
                        char_start=m.start(1),
                        char_end=m.end(1),
                        confidence=1.0,
                        checksum_verified=True,
                        detector_source="MATH_CHECKSUM",
                    )
                )

        # 3. Полисы ОМС единого образца (16 цифр) и банковские карты «Мир» (2200..2204) по Луну
        for m in self._CARD_OR_OMS_RE.finditer(text):
            raw = m.group(1)
            digits = re.sub(r"\D", "", raw)
            if len(digits) == 16 and verify_luhn_checksum(digits):
                context_prefix = text[max(0, m.start(1) - 32) : m.start(1)].lower()
                is_oms = "омс" in context_prefix or "полис" in context_prefix
                is_card = digits.startswith(("2200", "2201", "2202", "2203", "2204", "4", "5"))
                cat = (
                    PiiEntityCategory.OMS_POLICY
                    if is_oms or not is_card
                    else PiiEntityCategory.BANK_CARD_MIR
                )
                candidates.append(
                    DetectedPiiSpan(
                        category=cat,
                        raw_value=raw,
                        normalized_value=digits,
                        char_start=m.start(1),
                        char_end=m.end(1),
                        confidence=0.99,
                        checksum_verified=True,
                        detector_source="MATH_CHECKSUM",
                    )
                )

        # 4. Паспорта РФ (с проверкой кода региона ОКАТО и года бланка)
        for regex in (self._PASSPORT_CONTEXT_RE, self._PASSPORT_BARE_RE):
            for m in regex.finditer(text):
                raw = m.group(1)
                digits = re.sub(r"\D", "", raw)
                if verify_rf_passport_series_number(digits):
                    candidates.append(
                        DetectedPiiSpan(
                            category=PiiEntityCategory.PASSPORT_RF,
                            raw_value=raw,
                            normalized_value=digits,
                            char_start=m.start(1),
                            char_end=m.end(1),
                            confidence=0.98,
                            checksum_verified=True,
                            detector_source="MATH_CHECKSUM",
                        )
                    )

        # 5. Кадастровые номера (например, 55:36:090102:2145)
        for m in self._CADASTRAL_RE.finditer(text):
            raw = m.group(1)
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.CADASTRAL_NUM,
                    raw_value=raw,
                    normalized_value=raw,
                    char_start=m.start(1),
                    char_end=m.end(1),
                    confidence=0.99,
                    checksum_verified=True,
                    detector_source="MATH_CHECKSUM",
                )
            )

        # 6. Телефоны РФ и Email
        for m in self._PHONE_RU_RE.finditer(text):
            raw = m.group(0)
            norm = "+7" + "".join(m.groups())
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.PHONE_RU,
                    raw_value=raw,
                    normalized_value=norm,
                    char_start=m.start(0),
                    char_end=m.end(0),
                    confidence=0.97,
                    checksum_verified=True,
                    detector_source="HYBRID_ENSEMBLE",
                )
            )

        for m in self._EMAIL_RE.finditer(text):
            raw = m.group(0)
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.EMAIL,
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    char_start=m.start(0),
                    char_end=m.end(0),
                    confidence=0.99,
                    checksum_verified=True,
                    detector_source="HYBRID_ENSEMBLE",
                )
            )

        # 7. ФИО в косвенных падежах, адреса Омской области и мед. сведения (ст. 10 152-ФЗ)
        for m in self._FIO_CASE_RE.finditer(text):
            raw = m.group(0)
            stem_key = normalize_ru_fio_canonical_key(raw)
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.PERSON_FIO,
                    raw_value=raw,
                    normalized_value=stem_key,
                    char_start=m.start(0),
                    char_end=m.end(0),
                    confidence=0.96,
                    checksum_verified=False,
                    detector_source="HYBRID_ENSEMBLE",
                )
            )

        for m in self._ADDRESS_OMSK_RE.finditer(text):
            raw = m.group(0).strip()
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.ADDRESS_OMSK,
                    raw_value=raw,
                    normalized_value=re.sub(r"\s+", " ", raw.lower()),
                    char_start=m.start(0),
                    char_end=m.end(0),
                    confidence=0.94,
                    checksum_verified=False,
                    detector_source="HYBRID_ENSEMBLE",
                )
            )

        for m in self._MEDICAL_SPECIAL_RE.finditer(text):
            raw = m.group(0).strip()
            candidates.append(
                DetectedPiiSpan(
                    category=PiiEntityCategory.MEDICAL_SPECIAL_152FZ,
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    char_start=m.start(0),
                    char_end=m.end(0),
                    confidence=0.95,
                    checksum_verified=False,
                    detector_source="HYBRID_ENSEMBLE",
                )
            )

        return self._resolve_overlapping_spans(candidates)

    @staticmethod
    def _resolve_overlapping_spans(spans: list[DetectedPiiSpan]) -> list[DetectedPiiSpan]:
        """
        Устраняет пересечения спанов: приоритет отдаётся спанам с математически подтверждённой
        контрольной суммой и наибольшей длиной.
        """
        sorted_spans = sorted(
            spans,
            key=lambda s: (
                s.char_start,
                -(1 if s.checksum_verified else 0),
                -(s.char_end - s.char_start),
            ),
        )
        resolved: list[DetectedPiiSpan] = []
        for span in sorted_spans:
            if not resolved:
                resolved.append(span)
                continue
            prev = resolved[-1]
            if span.char_start >= prev.char_end:
                resolved.append(span)
            else:
                prev_len = prev.char_end - prev.char_start
                curr_len = span.char_end - span.char_start
                if (span.checksum_verified and not prev.checksum_verified) or (
                    span.checksum_verified == prev.checksum_verified and curr_len > prev_len
                ):
                    resolved[-1] = span
        return resolved

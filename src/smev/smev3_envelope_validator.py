# src/smev/smev3_envelope_validator.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from src.models.contracts import SmevAppealEnvelope, SmevAttachmentMeta


class SmevSecurityViolationError(ValueError):
    """Исключение безопасности периметра СМЭВ 3.0 (XXE, XML Bomb, SSRF, вредоносное вложение)."""


@dataclass(slots=True)
class SmevValidationResult:
    is_valid: bool
    message_id: str
    sender_mnemonic: str
    extracted_appeal_subject: str
    extracted_appeal_body: str
    security_warnings: list[str] = field(default_factory=list)


class Smev3EnvelopeValidator:
    """
    Валидатор XML/JSON-конвертов СМЭВ 3.0 и обращений граждан по 59-ФЗ для шлюза «Щит-АИСТ / СМЭВ-Guard».
    """

    MAX_XML_BYTES: int = 2 * 1024 * 1024  # 2 МБ на конверт СМЭВ 3.0
    MAX_XML_DEPTH: int = 16
    MAX_XML_ELEMENTS: int = 2500

    # Запрет любых DTD, ENTITY и внешних ссылок в теле XML (защита от XXE и Billion Laughs)
    _FORBIDDEN_XML_CONSTRUCTS_RE = re.compile(
        r"<!\s*(?:DOCTYPE|ENTITY)\b|SYSTEM\s+[\"']|PUBLIC\s+[\"']|xmlns:xi=",
        re.IGNORECASE,
    )

    # Поиск любых URI (включая опасные схемы file://, gopher://, dict://, ftp://, ldap://) для фильтрации SSRF/LFI
    _URL_EXTRACTOR_RE = re.compile(
        r"\b(?:https?|file|gopher|dict|ftp|ldap|ldaps|tftp|ws|wss)://[^\s<>\"')]+",
        re.IGNORECASE,
    )

    _DISALLOWED_URI_SCHEMES: frozenset[str] = frozenset(
        {"file", "gopher", "dict", "ftp", "ldap", "ldaps", "tftp", "ws", "wss"}
    )

    _FORBIDDEN_HOST_SUFFIXES: tuple[str, ...] = (
        ".internal",
        ".local",
        ".lan",
        ".corp",
        ".home.arpa",
        ".nip.io",
        ".sslip.io",
        ".xip.io",
    )

    _SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

    # Сигнатуры опасных вложений (PDF JavaScript/Launch и макросы MS Office / OpenXML)
    _MALICIOUS_ATTACHMENT_PATTERNS = (
        re.compile(
            r"/(?:JavaScript|JS|Launch|EmbeddedFiles|OpenAction|AA|RichMedia)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:AutoOpen|AutoExec|Document_Open|Workbook_Open|Shell\s*\(|WScript\.Shell|CreateObject)\b",
            re.IGNORECASE,
        ),
    )

    ALLOWED_MIME_TYPES: frozenset[str] = frozenset(
        {
            "application/pdf",
            "text/plain",
            "application/xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "image/jpeg",
            "image/png",
        }
    )

    def validate_envelope(self, envelope: SmevAppealEnvelope) -> SmevValidationResult:
        """
        Комплексная проверка конверта СМЭВ 3.0, его XML-структуры (если передана),
        SSRF-ссылок и безопасности всех приложенных файлов.
        """
        warnings: list[str] = []

        # 1. Если передан сырой XML-конверт СМЭВ 3.0 — выполняем жёсткую проверку анти-XXE и лимитов AST
        if envelope.raw_xml_envelope is not None:
            self._validate_raw_smev_xml(envelope.raw_xml_envelope)

        # 2. Проверка ссылок в теме и тексте обращения на SSRF во внутреннюю сеть ГИС (10.221.0.0/16 и др.)
        combined_text = f"{envelope.appeal_subject}\n{envelope.appeal_body}"
        self._check_no_internal_ssrf_urls(combined_text)

        # 3. Проверка каждого вложения СМЭВ (MIME-тип, SHA-256, отсутствие макросов и PDF-скриптов)
        total_attachment_bytes = 0
        for att in envelope.attachments:
            total_attachment_bytes += att.size_bytes
            if total_attachment_bytes > 25 * 1024 * 1024:
                raise SmevSecurityViolationError(
                    f"Превышена суммарная квота вложений пакета СМЭВ 3.0: {total_attachment_bytes} байт > 25 МБ."
                )
            self._validate_attachment(att, warnings)

        return SmevValidationResult(
            is_valid=True,
            message_id=envelope.message_id,
            sender_mnemonic=envelope.sender_mnemonic,
            extracted_appeal_subject=envelope.appeal_subject.strip(),
            extracted_appeal_body=envelope.appeal_body.strip(),
            security_warnings=warnings,
        )

    def _validate_raw_smev_xml(self, raw_xml: str) -> None:
        raw_bytes = raw_xml.encode("utf-8")
        if len(raw_bytes) > self.MAX_XML_BYTES:
            raise SmevSecurityViolationError(
                f"Превышен допустимый размер XML-конверта СМЭВ 3.0: {len(raw_bytes)} > {self.MAX_XML_BYTES} байт."
            )
        if self._FORBIDDEN_XML_CONSTRUCTS_RE.search(raw_xml):
            raise SmevSecurityViolationError(
                "CRITICAL XXE/XML-BOMB BLOCK: В конверте СМЭВ 3.0 обнаружены запрещённые директивы <!DOCTYPE / <!ENTITY / SYSTEM!"
            )
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError as exc:
            raise SmevSecurityViolationError(
                f"Нарушена синтаксическая схема XML СМЭВ 3.0: {exc}"
            ) from exc

        # Обход дерева с контролем глубины (анти-DoS), общего числа узлов и SSRF внутри XML-атрибутов
        element_count = 0
        stack: list[tuple[ET.Element, int]] = [(root, 1)]
        while stack:
            node, depth = stack.pop()
            element_count += 1
            if depth > self.MAX_XML_DEPTH:
                raise SmevSecurityViolationError(
                    f"Превышена максимальная глубина вложенности XML СМЭВ 3.0 ({depth} > {self.MAX_XML_DEPTH})."
                )
            if element_count > self.MAX_XML_ELEMENTS:
                raise SmevSecurityViolationError(
                    f"Превышено максимальное число элементов XML СМЭВ 3.0 ({element_count} > {self.MAX_XML_ELEMENTS})."
                )
            if node.text:
                self._check_no_internal_ssrf_urls(node.text)
            for attr_val in node.attrib.values():
                self._check_no_internal_ssrf_urls(attr_val)
            for child in list(node):
                stack.append((child, depth + 1))

    @staticmethod
    def _parse_ip_or_integer_literal(
        host: str,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """
        Распознаёт стандартные IPv4/IPv6-адреса, целочисленные 32-битные IP (например, 182255640 -> 10.221.0.24)
        и шестнадцатеричные IP-литералы (0x7f000001 -> 127.0.0.1), используемые для обхода SSRF-фильтров.
        """
        if host.isdigit():
            val = int(host)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        if host.startswith("0x") and all(c in "0123456789abcdef" for c in host[2:]):
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    def _check_no_internal_ssrf_urls(self, text: str) -> None:
        for match in self._URL_EXTRACTOR_RE.finditer(text):
            url_str = match.group(0)
            parsed = urlparse(url_str)
            scheme = (parsed.scheme or "").strip().lower()
            if scheme in self._DISALLOWED_URI_SCHEMES:
                raise SmevSecurityViolationError(
                    f"CRITICAL SSRF/LFI BLOCK: Запрещённая сетевая/файловая схема URI '{scheme}://' в '{url_str}'!"
                )
            host = (parsed.hostname or "").strip().lower()
            if not host:
                raise SmevSecurityViolationError(
                    f"CRITICAL SSRF BLOCK: Пустой или некорректный хост в URI '{url_str}'!"
                )
            if (
                host in ("localhost", "metadata.google.internal", "169.254.169.254", "0.0.0.0")
                or any(host.endswith(sfx) for sfx in self._FORBIDDEN_HOST_SUFFIXES)
            ):
                raise SmevSecurityViolationError(
                    f"CRITICAL SSRF BLOCK: Запрещённая ссылка на внутренний или rebinding-узел '{host}'!"
                )
            ip_obj = self._parse_ip_or_integer_literal(host)
            if ip_obj is None:
                continue
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise SmevSecurityViolationError(
                    f"CRITICAL SSRF BLOCK: Попытка обращения к защищённому внутреннему IP ГИС '{ip_obj}'!"
                )

    def _validate_attachment(self, att: SmevAttachmentMeta, warnings: list[str]) -> None:
        if att.mime_type not in self.ALLOWED_MIME_TYPES:
            raise SmevSecurityViolationError(
                f"Недопустимый MIME-тип вложения СМЭВ 3.0: '{att.mime_type}' (файл '{att.filename}')."
            )
        if not self._SHA256_HEX_RE.match(att.sha256_hex):
            raise SmevSecurityViolationError(
                f"Некорректная контрольная сумма SHA-256 вложения '{att.filename}'."
            )
        lower_name = att.filename.lower()
        if ".." in lower_name or "/" in lower_name or "\\" in lower_name:
            raise SmevSecurityViolationError(
                f"CRITICAL PATH TRAVERSAL BLOCK: Недопустимое имя файла вложения '{att.filename}'!"
            )
        if any(
            lower_name.endswith(ext)
            for ext in (".docm", ".xlsm", ".pptm", ".exe", ".bat", ".ps1", ".vbs", ".js")
        ):
            raise SmevSecurityViolationError(
                f"CRITICAL MACRO/EXEC BLOCK: Запрещённое расширение файла вложения '{att.filename}'!"
            )
        for pattern in self._MALICIOUS_ATTACHMENT_PATTERNS:
            if pattern.search(att.extracted_text):
                raise SmevSecurityViolationError(
                    f"CRITICAL PAYLOAD BLOCK: Во вложении '{att.filename}' обнаружена сигнатура макроса или активного скрипта!"
                )
        self._check_no_internal_ssrf_urls(att.extracted_text)
        if len(att.extracted_text) > 20000:
            warnings.append(
                f"Вложение '{att.filename}' содержит крупный текстовый блок ({len(att.extracted_text)} симв.)."
            )

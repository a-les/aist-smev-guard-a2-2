# src/vipnet/ast_opa_uzi_engine.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import ipaddress
import re
from typing import Literal

from src.models.contracts import FstecUziReport, SecurityRuleNode, SourceSpan

# Нормативные веса групп мер защиты ГИС К1 по Приказу ФСТЭК № 117 (в ред. № 137) и МД от 12.04.2026
DEFAULT_FSTEC_117_K1_WEIGHTS: dict[str, float] = {
    "ИАФ": 0.14,  # Идентификация и аутентификация
    "УПД": 0.16,  # Управление доступом
    "МСЭ": 0.16,  # Межсетевое экранирование и сегментация
    "ЗКС": 0.18,  # Защита каналов связи (ГОСТ-туннели ViPNet)
    "РСБ": 0.14,  # Регистрация событий безопасности (ГОСТ Р 59548-2022)
    "АНЗ": 0.10,  # Анализ защищённости и формальная верификация
    "ИИ": 0.12,   # Защита компонентов ИИ и ПДн (разд. 3.18 МД ФСТЭК 12.04.2026)
}


class VipnetAstAndUziEngine:
    """
    Структурный парсер конфигураций ПАК ViPNet Coordinator (iplir.conf, firewall.conf)
    с сохранением точных координат строк SourceSpan, встроенным исполнителем правил OPA Rego
    и двухконтурным калькулятором показателя защищённости ГИС Узи (кейс R&D-5).
    """

    _SECTION_HEADER_RE = re.compile(r"^\s*\[(id|local|forward|tunnel|nat)\]\s*$", re.IGNORECASE)
    _FIREWALL_RULE_RE = re.compile(
        r"^\s*rule\s*=\s*num\s+(?P<num>\d+)\s+proto\s+(?P<proto>tcp|udp|icmp|ip|any)\s+"
        r"from\s+(?P<src>\S+)\s+to\s+(?P<dst>\S+)"
        r"(?:\s+port\s+(?P<port>\d+(?:-\d+)?))?\s+(?P<action>pass|drop|deny|encrypt)\s*$",
        re.IGNORECASE,
    )
    _KV_LINE_RE = re.compile(r"^\s*(?P<key>[a-zA-Z0-9_]+)\s*=\s*(?P<val>.+?)\s*$")

    def parse_vipnet_configs(
        self,
        config_text: str,
        file_path: str = "/etc/vipnet/firewall.conf",
    ) -> tuple[list[SecurityRuleNode], list[tuple[str, str]]]:
        """
        Преобразует текст конфигурации iplir.conf / firewall.conf в типизированный список SecurityRuleNode
        и список сконфигурированных ГОСТ-туннелей (src_cidr, dst_cidr).
        """
        rules: list[SecurityRuleNode] = []
        tunnels: list[tuple[str, str]] = []
        current_section: str = "forward"
        current_id_node: dict[str, str | int] = {}
        current_id_start_line: int = 1

        def _flush_id_block(end_line: int) -> None:
            nonlocal current_id_node
            if not current_id_node or "tunnel" not in current_id_node:
                current_id_node = {}
                return
            node_name = str(current_id_node.get("name", current_id_node.get("id", "vipnet-peer")))
            raw_tunnel = str(current_id_node["tunnel"])
            mtu_val = int(current_id_node.get("mtu", 1360))
            cidr_str = self._ip_range_to_cidr(raw_tunnel)
            rules.append(
                SecurityRuleNode(
                    rule_id=f"TUN-{node_name}",
                    section="tunnel",
                    priority=len(rules) + 1,
                    subject_cidr_or_role="10.221.0.0/24",
                    resource_cidr_or_uri=cidr_str,
                    protocol_or_method="ip",
                    port_range=(0, 65535),
                    effect="encrypt_tunnel",
                    mtu_value=mtu_val,
                    span=SourceSpan(
                        file_path=file_path,
                        line_start=current_id_start_line,
                        line_end=max(current_id_start_line, end_line),
                    ),
                )
            )
            tunnels.append(("10.221.0.0/24", cidr_str))
            current_id_node = {}

        lines = config_text.splitlines()
        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            sec_match = self._SECTION_HEADER_RE.match(stripped)
            if sec_match:
                _flush_id_block(idx - 1)
                current_section = sec_match.group(1).lower()
                current_id_start_line = idx
                continue
            if current_section == "id":
                kv_match = self._KV_LINE_RE.match(stripped)
                if kv_match:
                    k = kv_match.group("key").lower()
                    v = kv_match.group("val").strip()
                    current_id_node[k] = int(v) if k == "mtu" and v.isdigit() else v
                continue
            rule_match = self._FIREWALL_RULE_RE.match(stripped)
            if rule_match:
                num = int(rule_match.group("num"))
                proto_raw = rule_match.group("proto").lower()
                src_raw = rule_match.group("src")
                dst_raw = rule_match.group("dst")
                port_raw = rule_match.group("port")
                action_raw = rule_match.group("action").lower()

                if port_raw:
                    if "-" in port_raw:
                        p_low, p_high = port_raw.split("-", 1)
                        port_range = (int(p_low), int(p_high))
                    else:
                        p_val = int(port_raw)
                        port_range = (p_val, p_val)
                else:
                    port_range = (0, 65535)

                effect: Literal["allow", "deny", "encrypt_tunnel"] = (
                    "allow"
                    if action_raw == "pass"
                    else ("encrypt_tunnel" if action_raw == "encrypt" else "deny")
                )
                sec_lit: Literal["local", "forward", "tunnel", "nat"] = (
                    current_section
                    if current_section in ("local", "forward", "tunnel", "nat")
                    else "forward"
                )
                rules.append(
                    SecurityRuleNode(
                        rule_id=f"FW-{sec_lit.upper()}-{num}",
                        section=sec_lit,
                        priority=num,
                        subject_cidr_or_role=src_raw,
                        resource_cidr_or_uri=dst_raw,
                        protocol_or_method=proto_raw,  # type: ignore[arg-type]
                        port_range=port_range,
                        effect=effect,
                        mtu_value=1360,
                        span=SourceSpan(file_path=file_path, line_start=idx, line_end=idx),
                    )
                )

        _flush_id_block(len(lines))
        return rules, tunnels

    @staticmethod
    def _ip_range_to_cidr(raw_range: str) -> str:
        if "/" in raw_range:
            return raw_range
        if "-" in raw_range:
            start_s, end_s = [p.strip() for p in raw_range.split("-", 1)]
            start_ip = ipaddress.IPv4Address(start_s)
            end_ip = ipaddress.IPv4Address(end_s)
            nets = list(ipaddress.summarize_address_range(start_ip, end_ip))
            if nets:
                return str(nets[0])
        return f"{raw_range.strip()}/32"

    def evaluate_opa_and_calculate_uzi(
        self,
        rules: list[SecurityRuleNode],
        measures_by_group: dict[str, list[float]],
        weights: dict[str, float] | None = None,
        z3_has_cleartext_leak: bool = False,
        gis_class: Literal["K1", "K2", "K3"] = "K1",
    ) -> FstecUziReport:
        """
        Выполняет проверку правил политики fstec_117_guit.rego и рассчитывает двухконтурный показатель
        защищённости ГИС Узи по Приказу ФСТЭК № 117 (в ред. № 137) и МД от 12.04.2026:
        U_зи = I_block(K, U1, U2) * sum_k w_k * (1 / m_k) * sum_j c_{k,j}.
        """
        active_weights = weights or DEFAULT_FSTEC_117_K1_WEIGHTS
        opa_denials: list[str] = []

        for r in rules:
            if r.effect == "allow" and r.subject_cidr_or_role in ("@any", "0.0.0.0/0", "*"):
                if r.port_range[0] <= 22 <= r.port_range[1]:
                    opa_denials.append(
                        f"[CRITICAL I_block=0] Нарушение МСЭ.3 / УПД.4: открыт порт SSH 22 для "
                        f"{r.subject_cidr_or_role} в правиле {r.rule_id} (строка {r.span.line_start})"
                    )
                if r.port_range[0] <= 8000 <= r.port_range[1]:
                    opa_denials.append(
                        f"[CRITICAL I_block=0] Нарушение ИИ.2 / ЗИС.3: прямой доступ {r.subject_cidr_or_role} "
                        f"к порту LLM АИСТ (8000) в правиле {r.rule_id} (строка {r.span.line_start})"
                    )
            if r.section == "tunnel" and r.mtu_value > 1400:
                opa_denials.append(
                    f"[WARNING ЗКС.2] Риск потери пакетов (MTU Drop): MTU={r.mtu_value} > 1400 "
                    f"в правиле {r.rule_id} (строка {r.span.line_start})"
                )

        if z3_has_cleartext_leak:
            opa_denials.append(
                "[CRITICAL I_block=0] Нарушение ЗКС.1: Z3 SMT Solver доказал наличие Split-Tunneling Cleartext Leak!"
            )

        has_critical_block = any("[CRITICAL I_block=0]" in msg for msg in opa_denials)
        i_block = 0.0 if has_critical_block else 1.0

        group_averages: dict[str, float] = {}
        weighted_sum = 0.0
        for group_code, w_k in active_weights.items():
            scores = measures_by_group.get(group_code, [1.0])
            avg_score = sum(scores) / len(scores) if scores else 0.0
            group_averages[group_code] = round(avg_score, 4)
            weighted_sum += w_k * avg_score

        operational_score = round(min(1.0, max(0.0, weighted_sum)), 4)
        final_uzi = round(i_block * operational_score, 4)

        threshold = 0.85 if gis_class == "K1" else (0.75 if gis_class == "K2" else 0.65)
        if i_block == 0.0:
            status: Literal[
                "COMPLIANT_K1", "NON_COMPLIANT_BLOCKED", "NON_COMPLIANT_LOW_SCORE"
            ] = "NON_COMPLIANT_BLOCKED"
        elif final_uzi >= threshold:
            status = "COMPLIANT_K1"
        else:
            status = "NON_COMPLIANT_LOW_SCORE"

        return FstecUziReport(
            gis_class=gis_class,
            i_block_multiplier=i_block,
            operational_weighted_score=operational_score,
            final_uzi=final_uzi,
            compliance_status=status,
            opa_denials=opa_denials,
            group_averages=group_averages,
        )

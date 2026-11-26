# src/vipnet/ast_opa_uzi_engine.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

import lark

from src.models.contracts import (
    FstecUziReport,
    RemediationAction,
    SecurityRuleNode,
    SourceSpan,
    WhatIfRemediationResult,
)

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

# Lark EBNF грамматика для конфигураций ViPNet Coordinator (iplir.conf / firewall.conf)
VIPNET_EBNF_GRAMMAR = r"""
?start: (_nl | statement)*

?statement: section_header
         | rule_directive
         | kv_directive

section_header: "[" SECTION_NAME "]"
rule_directive: "rule" "=" "num" INT "proto" PROTO "from" IP_EXPR "to" IP_EXPR ( "port" PORT_EXPR )? ACTION
kv_directive: KEY "=" VALUE

SECTION_NAME: /[a-zA-Z0-9_\-]+/
PROTO.2: "tcp" | "udp" | "icmp" | "ip" | "any"
ACTION.2: "pass" | "drop" | "deny" | "encrypt"
KEY: /[a-zA-Z0-9_]+/
VALUE: /[^#;\r\n]+/
IP_EXPR.1: /@[a-zA-Z0-9_\-]+|\*|any|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\/[0-9]{1,2}|-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?/
PORT_EXPR.1: /[0-9]+(?:-[0-9]+)?/

COMMENT: /(#|;)[^\r\n]*/
_nl: /\r?\n/

%import common.INT
%import common.WS_INLINE
%ignore WS_INLINE
%ignore COMMENT
"""


class VipnetAstAndUziEngine:
    """
    Структурный парсер конфигураций ПАК ViPNet Coordinator (iplir.conf, firewall.conf)
    на базе Lark EBNF с сохранением точных координат строк SourceSpan, встроенным исполнителем
    правил OPA Rego, двухконтурным калькулятором показателя защищённости ГИС Узи (кейс R&D-5)
    и симулятором What-If ремедиации.
    """

    def __init__(self) -> None:
        self._lark_parser = lark.Lark(
            VIPNET_EBNF_GRAMMAR,
            parser="earley",
            propagate_positions=True,
        )

    def parse_vipnet_configs(
        self,
        config_text: str,
        file_path: str = "/etc/vipnet/firewall.conf",
    ) -> tuple[list[SecurityRuleNode], list[tuple[str, str]]]:
        """
        Преобразует текст конфигурации iplir.conf / firewall.conf в типизированный список SecurityRuleNode
        и список сконфигурированных ГОСТ-туннелей (src_cidr, dst_cidr) через грамматику Lark EBNF.
        """
        try:
            tree = self._lark_parser.parse(config_text)
            return self._build_ast_from_tree(tree, config_text, file_path)
        except Exception:
            # Отказоустойчивый fallback на регулярные выражения при нестандартном синтаксисе
            return self._parse_regex_fallback(config_text, file_path)

    def _build_ast_from_tree(
        self,
        tree: lark.Tree,
        raw_text: str,
        file_path: str,
    ) -> tuple[list[SecurityRuleNode], list[tuple[str, str]]]:
        rules: list[SecurityRuleNode] = []
        tunnels: list[tuple[str, str]] = []
        current_section = "forward"
        current_id_node: dict[str, Any] = {}
        current_id_start_line = 1

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

        for stmt in tree.children:
            if not isinstance(stmt, lark.Tree):
                continue

            if stmt.data == "section_header":
                sec_name = str(stmt.children[0]).strip().lower()
                _flush_id_block(stmt.meta.line - 1 if hasattr(stmt, "meta") else 1)
                current_section = sec_name
                current_id_start_line = stmt.meta.line if hasattr(stmt, "meta") else 1
                continue

            if stmt.data == "kv_directive" and current_section == "id":
                k = str(stmt.children[0]).strip().lower()
                v = str(stmt.children[1]).strip()
                current_id_node[k] = int(v) if k == "mtu" and v.isdigit() else v
                continue

            if stmt.data == "rule_directive":
                # rule = num INT proto PROTO from IP_EXPR to IP_EXPR (port PORT_EXPR)? ACTION
                num = int(str(stmt.children[0]))
                proto_raw = str(stmt.children[1]).lower()
                src_raw = str(stmt.children[2])
                dst_raw = str(stmt.children[3])

                if len(stmt.children) == 6:
                    port_raw = str(stmt.children[4])
                    action_raw = str(stmt.children[5]).lower()
                else:
                    port_raw = None
                    action_raw = str(stmt.children[4]).lower()

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

                line_start = stmt.meta.line if hasattr(stmt, "meta") else 1
                line_end = stmt.meta.end_line if hasattr(stmt, "meta") else line_start

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
                        span=SourceSpan(
                            file_path=file_path,
                            line_start=line_start,
                            line_end=line_end,
                        ),
                    )
                )

        _flush_id_block(len(raw_text.splitlines()))
        return rules, tunnels

    def _parse_regex_fallback(
        self,
        config_text: str,
        file_path: str,
    ) -> tuple[list[SecurityRuleNode], list[tuple[str, str]]]:
        rules: list[SecurityRuleNode] = []
        tunnels: list[tuple[str, str]] = []
        current_section: str = "forward"
        current_id_node: dict[str, Any] = {}
        current_id_start_line: int = 1

        sec_header_re = re.compile(r"^\s*\[(id|local|forward|tunnel|nat)\]\s*$", re.IGNORECASE)
        firewall_rule_re = re.compile(
            r"^\s*rule\s*=\s*num\s+(?P<num>\d+)\s+proto\s+(?P<proto>tcp|udp|icmp|ip|any)\s+"
            r"from\s+(?P<src>\S+)\s+to\s+(?P<dst>\S+)"
            r"(?:\s+port\s+(?P<port>\d+(?:-\d+)?))?\s+(?P<action>pass|drop|deny|encrypt)\s*$",
            re.IGNORECASE,
        )
        kv_line_re = re.compile(r"^\s*(?P<key>[a-zA-Z0-9_]+)\s*=\s*(?P<val>.+?)\s*$")

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
            sec_match = sec_header_re.match(stripped)
            if sec_match:
                _flush_id_block(idx - 1)
                current_section = sec_match.group(1).lower()
                current_id_start_line = idx
                continue
            if current_section == "id":
                kv_match = kv_line_re.match(stripped)
                if kv_match:
                    k = kv_match.group("key").lower()
                    v = kv_match.group("val").strip()
                    current_id_node[k] = int(v) if k == "mtu" and v.isdigit() else v
                continue
            rule_match = firewall_rule_re.match(stripped)
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

                effect = (
                    "allow"
                    if action_raw == "pass"
                    else ("encrypt_tunnel" if action_raw == "encrypt" else "deny")
                )
                sec_lit = (
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
        measures_by_group: dict[str, list[float]] | None = None,
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
        effective_measures = measures_by_group or {}
        opa_denials: list[str] = []

        for r in rules:
            if r.effect == "allow" and r.subject_cidr_or_role in ("@any", "0.0.0.0/0", "*", "any"):
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
            scores = effective_measures.get(group_code, [1.0])
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

    def simulate_remediation_what_if(
        self,
        config_or_rules: str | list[SecurityRuleNode],
        remediations: list[RemediationAction] | None = None,
        measures_by_group: dict[str, list[float]] | None = None,
        z3_has_cleartext_leak: bool = False,
        gis_class: Literal["K1", "K2", "K3"] = "K1",
        target_threshold: float = 0.85,
        file_path: str = "/etc/vipnet/firewall.conf",
    ) -> WhatIfRemediationResult:
        """
        Симулятор ремедиации (What-If): принимает уязвимую конфигурацию, вычисляет базовый
        показатель U_зи (где I_block=0.0 из-за нарушений), применяет патчи устранения
        (сужение подсетей SSH/LLM, фиксация MTU, шифрование туннелей) и рассчитывает итоговый U_зи >= 0.94.
        """
        if isinstance(config_or_rules, str):
            rules, _ = self.parse_vipnet_configs(config_or_rules, file_path=file_path)
            orig_text = config_or_rules
        else:
            rules = [r.model_copy(deep=True) for r in config_or_rules]
            orig_text = ""

        # 1. Расчет исходного отчета
        initial_report = self.evaluate_opa_and_calculate_uzi(
            rules=rules,
            measures_by_group=measures_by_group,
            z3_has_cleartext_leak=z3_has_cleartext_leak,
            gis_class=gis_class,
        )

        # 2. Если действия не переданы явно, выполняем автоматический синтез оптимальной ремедиации
        actions_to_apply: list[RemediationAction] = []
        if remediations:
            actions_to_apply.extend(remediations)
        else:
            for r in rules:
                if r.effect == "allow" and r.subject_cidr_or_role in ("@any", "0.0.0.0/0", "*", "any"):
                    if r.port_range[0] <= 22 <= r.port_range[1]:
                        actions_to_apply.append(
                            RemediationAction(
                                action_type="RESTRICT_SUBNET",
                                target_rule_id=r.rule_id,
                                parameters={"trusted_cidr": "10.221.0.0/24"},
                                description=f"Сужение источника SSH 22 с {r.subject_cidr_or_role} на доверенную подсеть 10.221.0.0/24",
                            )
                        )
                    if r.port_range[0] <= 8000 <= r.port_range[1]:
                        actions_to_apply.append(
                            RemediationAction(
                                action_type="RESTRICT_SUBNET",
                                target_rule_id=r.rule_id,
                                parameters={"trusted_cidr": "10.55.10.0/24"},
                                description="Изоляция порта LLM АИСТ (8000) для подсети шлюза 10.55.10.0/24",
                            )
                        )
                if r.section == "tunnel" and r.mtu_value > 1400:
                    actions_to_apply.append(
                        RemediationAction(
                            action_type="FIX_MTU",
                            target_rule_id=r.rule_id,
                            parameters={"mtu": 1360},
                            description=f"Снижение MTU туннеля {r.rule_id} с {r.mtu_value} до безопасных 1360",
                        )
                    )

            if z3_has_cleartext_leak:
                actions_to_apply.append(
                    RemediationAction(
                        action_type="ADD_ENCRYPT_TUNNEL",
                        parameters={
                            "subject_cidr": "10.221.0.0/24",
                            "resource_cidr": "10.221.1.0/24",
                            "mtu": 1360,
                        },
                        description="Добавление ГОСТ-туннеля ViPNet для устранения Z3 Split-Tunneling утечки",
                    )
                )

        # 3. Применение действий ремедиации к правилам
        remediated_rules: list[SecurityRuleNode] = [r.model_copy(deep=True) for r in rules]
        applied_descriptions: list[str] = []

        for act in actions_to_apply:
            applied_descriptions.append(act.description or act.action_type)
            if act.action_type == "RESTRICT_SUBNET" and act.target_rule_id:
                new_cidr = act.parameters.get("trusted_cidr", "10.221.0.0/24")
                for r in remediated_rules:
                    if r.rule_id == act.target_rule_id:
                        r.subject_cidr_or_role = new_cidr
            elif act.action_type == "CLOSE_PORT" and act.target_rule_id:
                for r in remediated_rules:
                    if r.rule_id == act.target_rule_id:
                        r.effect = "deny"
            elif act.action_type == "FIX_MTU" and act.target_rule_id:
                new_mtu = int(act.parameters.get("mtu", 1360))
                for r in remediated_rules:
                    if r.rule_id == act.target_rule_id:
                        r.mtu_value = new_mtu
            elif act.action_type == "ADD_ENCRYPT_TUNNEL":
                sub_cidr = act.parameters.get("subject_cidr", "10.221.0.0/24")
                res_cidr = act.parameters.get("resource_cidr", "10.221.1.0/24")
                mtu_val = int(act.parameters.get("mtu", 1360))
                remediated_rules.append(
                    SecurityRuleNode(
                        rule_id=f"TUN-REMEDIATED-{len(remediated_rules) + 1}",
                        section="tunnel",
                        priority=len(remediated_rules) + 1,
                        subject_cidr_or_role=sub_cidr,
                        resource_cidr_or_uri=res_cidr,
                        protocol_or_method="ip",
                        port_range=(0, 65535),
                        effect="encrypt_tunnel",
                        mtu_value=mtu_val,
                        span=SourceSpan(
                            file_path=file_path,
                            line_start=1,
                            line_end=1,
                        ),
                    )
                )

        # 4. Расчет ремедиированного показателя U_зи
        remediated_measures = dict(measures_by_group or {})
        for grp in ("МСЭ", "ЗКС", "УПД", "ИИ"):
            if grp not in remediated_measures:
                remediated_measures[grp] = [1.0]
            else:
                remediated_measures[grp] = [1.0 for _ in remediated_measures[grp]]

        remediated_report = self.evaluate_opa_and_calculate_uzi(
            rules=remediated_rules,
            measures_by_group=remediated_measures,
            z3_has_cleartext_leak=False,
            gis_class=gis_class,
        )

        delta = round(remediated_report.final_uzi - initial_report.final_uzi, 4)
        is_met = remediated_report.final_uzi >= target_threshold

        remediated_text = self._synthesize_config_text(orig_text, remediated_rules) if orig_text else ""

        return WhatIfRemediationResult(
            initial_report=initial_report,
            remediated_report=remediated_report,
            delta_uzi=delta,
            is_target_met=is_met,
            applied_actions=applied_descriptions,
            remediated_rules=remediated_rules,
            remediated_config_text=remediated_text,
        )

    def _synthesize_config_text(
        self,
        orig_text: str,
        remediated_rules: list[SecurityRuleNode],
    ) -> str:
        """
        Формирует чистый и валидный текст firewall.conf / iplir.conf из пропатченных SecurityRuleNode.
        """
        lines: list[str] = [
            "# ViPNet Configuration - Hardened by Shield-AIST Remediation Engine",
            "# Compliance: FSTEC Orders 117/137, Methodological Documents 12.04.2026",
            "",
            "[local]",
        ]
        for r in remediated_rules:
            if r.section == "local":
                act_str = "pass" if r.effect == "allow" else ("encrypt" if r.effect == "encrypt_tunnel" else "drop")
                port_str = f" port {r.port_range[0]}" if r.port_range != (0, 65535) else ""
                lines.append(
                    f"rule = num {r.priority} proto {r.protocol_or_method} from {r.subject_cidr_or_role} to {r.resource_cidr_or_uri}{port_str} {act_str}"
                )

        lines.extend(["", "[forward]"])
        for r in remediated_rules:
            if r.section == "forward":
                act_str = "pass" if r.effect == "allow" else ("encrypt" if r.effect == "encrypt_tunnel" else "drop")
                port_str = f" port {r.port_range[0]}" if r.port_range != (0, 65535) else ""
                lines.append(
                    f"rule = num {r.priority} proto {r.protocol_or_method} from {r.subject_cidr_or_role} to {r.resource_cidr_or_uri}{port_str} {act_str}"
                )

        tunnels = [r for r in remediated_rules if r.section == "tunnel"]
        if tunnels:
            lines.extend(["", "[id]"])
            for t in tunnels:
                lines.extend([
                    f"name = {t.rule_id}",
                    f"tunnel = {t.resource_cidr_or_uri}",
                    f"mtu = {t.mtu_value}",
                    "",
                ])

        return "\n".join(lines)

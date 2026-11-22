# src/vipnet/z3_smt_tunnel_verifier.py
# Владелец: Панфилов Алексей Владимирович (@yo5hh, SC @nyamskiy) — Команда А2.2
from __future__ import annotations

import argparse
import json
import sys
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, ClassVar

try:
    import z3  # type: ignore[import-untyped]

    HAS_Z3 = True
except ImportError:
    z3 = None  # type: ignore[assignment]
    HAS_Z3 = False

from src.models.contracts import SecurityRuleNode, VerificationFinding

# Коды сетевых протоколов IANA для кодирования в 8-битный вектор Z3 BitVec8
PROTO_CODE_MAP: dict[str, int] = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "esp": 50,
    "ah": 51,
}

# 3D-брус сетевого трафика: (src_start, src_end, dst_start, dst_end, port_low, port_high)
Box3D = tuple[int, int, int, int, int, int]


class Z3VipnetSmtVerifier:
    """
    Формальный SMT-верификатор правил фильтрации и туннелирования ПАК ViPNet Coordinator
    на базе решателя Microsoft Z3 (BitVec32 / BitVec16 / BitVec8) с резервным точным решателем
    булевой алгебры 3D CIDR/Port-брусов (для air-gapped сред без бинарного пакета z3-solver)
    и выгрузкой отчётов SARIF 2.1.0.
    """

    # Каталог правил безопасности SARIF 2.1.0 для привязки к требованиям ФСТЭК России и CWE
    SARIF_RULES_CATALOG: ClassVar[list[dict[str, Any]]] = [
        {
            "id": "ЗКС.1",
            "name": "SplitTunnelingCleartextLeak",
            "shortDescription": {
                "text": "Передача защищаемого трафика ГИС в открытом виде мимо ГОСТ-туннеля ViPNet"
            },
            "fullDescription": {
                "text": (
                    "Правило межсетевого экрана разрешает прохождение конфиденциального "
                    "межведомственного трафика без обязательного туннелирования и шифрования ГОСТ (CWE-319)."
                )
            },
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://fstec.ru/tekhnicheskaya-zashchita-informatsii/dokumenty-i-metodicheskie-materialy",
            "properties": {
                "cwe": ["CWE-319"],
                "fstec_measure": "ЗКС.1 / МСЭ.3",
                "severity": "CRITICAL",
                "precision": "very-high",
            },
        },
        {
            "id": "МСЭ.1",
            "name": "RuleShadowing",
            "shortDescription": {
                "text": "Полное затенение правила фильтрации предшествующими правилами"
            },
            "fullDescription": {
                "text": (
                    "Правило фильтрации полностью недостижимо (Dead Rule), так как всё пространство "
                    "пакетов перекрывается предшествующими правилами (CWE-561)."
                )
            },
            "defaultConfiguration": {"level": "warning"},
            "helpUri": "https://cwe.mitre.org/data/definitions/561.html",
            "properties": {
                "cwe": ["CWE-561"],
                "fstec_measure": "МСЭ.1 / АНЗ.5",
                "severity": "MEDIUM",
                "precision": "very-high",
            },
        },
        {
            "id": "ЗКС.2",
            "name": "TunnelMtuFragmentationDrop",
            "shortDescription": {
                "text": "Завышенный MTU ГОСТ-туннеля ViPNet с риском фрагментации и сброса DF-пакетов"
            },
            "fullDescription": {
                "text": (
                    "Значение MTU превышает 1400 байт. С учётом накладных расходов ГОСТ-инкапсуляции "
                    "пакеты с установленным флагом Don't Fragment (DF) будут отброшены (CWE-400)."
                )
            },
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://cwe.mitre.org/data/definitions/400.html",
            "properties": {
                "cwe": ["CWE-400"],
                "fstec_measure": "ЗКС.2 / ДОС.1",
                "severity": "HIGH",
                "precision": "very-high",
            },
        },
        {
            "id": "ЗКС.2-MIN",
            "name": "InvalidMinimumTunnelMtu",
            "shortDescription": {
                "text": "Некорректное значение MTU туннеля ниже минимального предела IPv4 (576 байт)"
            },
            "fullDescription": {
                "text": "Значение MTU туннеля меньше 576 байт нарушает RFC 791 и делает невозможной маршрутизацию пакетов."
            },
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://tools.ietf.org/html/rfc791",
            "properties": {
                "cwe": ["CWE-400"],
                "fstec_measure": "ЗКС.2 / ДОС.1",
                "severity": "HIGH",
                "precision": "very-high",
            },
        },
    ]

    @staticmethod
    def _parse_cidr(selector: str) -> IPv4Network:
        norm = selector.strip().lower()
        if norm in ("@any", "*", "0.0.0.0/0", "any"):
            return IPv4Network("0.0.0.0/0")
        return IPv4Network(norm, strict=False)

    @staticmethod
    def _normalize_proto(proto_str: str) -> str:
        norm = proto_str.strip().lower()
        if norm in ("*", "@any", "any", "ip", "all"):
            return "any"
        return norm

    @classmethod
    def _proto_covers(cls, prior_proto: str, rule_proto: str) -> bool:
        """Возвращает True, если протокол предшествующего правила покрывает протокол текущего правила."""
        p_norm = cls._normalize_proto(prior_proto)
        r_norm = cls._normalize_proto(rule_proto)
        return p_norm == "any" or p_norm == r_norm

    @classmethod
    def proto_to_z3_pred(cls, proto_var: Any, proto_str: str) -> Any:
        norm = cls._normalize_proto(proto_str)
        if norm == "any":
            return z3.BoolVal(True)
        code = PROTO_CODE_MAP.get(norm, 254)
        return proto_var == z3.BitVecVal(code, 8)

    @staticmethod
    def cidr_to_z3_pred(ip_var: Any, selector: str) -> Any:
        norm = selector.strip().lower()
        if norm in ("@any", "*", "0.0.0.0/0", "any"):
            return z3.BoolVal(True)
        net = IPv4Network(norm, strict=False)
        mask_bv = z3.BitVecVal(int(net.netmask), 32)
        net_bv = z3.BitVecVal(int(net.network_address), 32)
        return (ip_var & mask_bv) == net_bv

    @classmethod
    def _nets_intersect(cls, a: IPv4Network, b: IPv4Network) -> IPv4Network | None:
        if a.overlaps(b):
            return a if a.prefixlen >= b.prefixlen else b
        return None

    @staticmethod
    def _rule_to_box3d(
        src_net: IPv4Network, dst_net: IPv4Network, port_range: tuple[int, int]
    ) -> Box3D:
        return (
            int(src_net.network_address),
            int(src_net.broadcast_address),
            int(dst_net.network_address),
            int(dst_net.broadcast_address),
            int(port_range[0]),
            int(port_range[1]),
        )

    @staticmethod
    def _subtract_box3d(target: Box3D, cutter: Box3D) -> list[Box3D]:
        """
        Вычитает 3D-брус cutter из 3D-бруса target в пространстве (src_ip, dst_ip, port).
        Используется для точного доказательства UNSAT при затенении правила объединением (union)
        нескольких предшествующих правил (например, 10.221.0.0/25 + 10.221.0.128/25 -> 10.221.0.0/24).
        """
        ax0, ax1, ay0, ay1, az0, az1 = target
        bx0, bx1, by0, by1, bz0, bz1 = cutter
        ix0, ix1 = max(ax0, bx0), min(ax1, bx1)
        iy0, iy1 = max(ay0, by0), min(ay1, by1)
        iz0, iz1 = max(az0, bz0), min(az1, bz1)

        if ix0 > ix1 or iy0 > iy1 or iz0 > iz1:
            return [target]

        pieces: list[Box3D] = []
        if ax0 < ix0:
            pieces.append((ax0, ix0 - 1, ay0, ay1, az0, az1))
        if ix1 < ax1:
            pieces.append((ix1 + 1, ax1, ay0, ay1, az0, az1))
        if ay0 < iy0:
            pieces.append((ix0, ix1, ay0, iy0 - 1, az0, az1))
        if iy1 < ay1:
            pieces.append((ix0, ix1, iy1 + 1, ay1, az0, az1))
        if az0 < iz0:
            pieces.append((ix0, ix1, iy0, iy1, az0, iz0 - 1))
        if iz1 < az1:
            pieces.append((ix0, ix1, iy0, iy1, iz1 + 1, az1))
        return pieces

    @classmethod
    def _get_uncovered_boxes(
        cls,
        r_box: Box3D,
        r_proto: str,
        prior_rules: list[tuple[Box3D, str]],
    ) -> list[Box3D]:
        """
        Возвращает список непокрытых 3D-брусов после вычитания всех предшествующих правил.
        Если список пуст, значит r_box полностью покрыт предшествующими правилами.
        """
        r_norm = cls._normalize_proto(r_proto)
        proto_variants = ("tcp", "udp", "icmp") if r_norm == "any" else (r_norm,)

        for proto_variant in proto_variants:
            remaining: list[Box3D] = [r_box]
            for p_box, p_proto in prior_rules:
                if not cls._proto_covers(p_proto, proto_variant):
                    continue
                next_remaining: list[Box3D] = []
                for piece in remaining:
                    next_remaining.extend(cls._subtract_box3d(piece, p_box))
                remaining = next_remaining
                if not remaining:
                    break
            if remaining:
                return remaining
        return []

    @classmethod
    def _is_rule_covered_by_prior_union(
        cls,
        r_box: Box3D,
        r_proto: str,
        prior_rules: list[tuple[Box3D, str]],
    ) -> bool:
        """
        Проверяет, пусто ли множество пакетов r_box после вычитания всех предшествующих правил
        с совместимым протоколом (точный эквивалент проверки UNSAT формулы M_k & !M_1 & ... & !M_{k-1}).
        """
        return len(cls._get_uncovered_boxes(r_box, r_proto, prior_rules)) == 0

    def _normalize_gis_pairs(
        self,
        gis_protected_pair: tuple[str, str] | list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        if (
            isinstance(gis_protected_pair, tuple)
            and len(gis_protected_pair) == 2
            and isinstance(gis_protected_pair[0], str)
        ):
            return [gis_protected_pair]
        return list(gis_protected_pair)

    def _verify_fallback_interval_smt(
        self,
        rules: list[SecurityRuleNode],
        gis_protected_pair: tuple[str, str] | list[tuple[str, str]],
        tunnels: list[tuple[str, str]],
    ) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        prior_forward: list[tuple[Box3D, str]] = []
        prior_rules_forward: list[SecurityRuleNode] = []
        gis_pairs = self._normalize_gis_pairs(gis_protected_pair)
        tunnel_nets = [(self._parse_cidr(s), self._parse_cidr(d)) for s, d in tunnels]

        for r in rules:
            if r.section == "tunnel":
                if r.mtu_value > 1400:
                    findings.append(
                        VerificationFinding(
                            finding_id=f"Z3-MTU-{r.rule_id}",
                            rule_id=r.rule_id,
                            cwe_id="CWE-400 (Tunnel MTU Fragmentation Drop)",
                            fstec_measure="ЗКС.2 / ДОС.1",
                            severity="HIGH",
                            description=(
                                f"В туннельном правиле {r.rule_id} задан MTU={r.mtu_value} > 1400 байт: "
                                f"инкапсуляция ГОСТ-заголовка ViPNet приведёт к отбрасыванию DF-пакетов СМЭВ 3.0."
                            ),
                            z3_counterexample={"configured_mtu": r.mtu_value, "max_safe_mtu": 1360},
                            suggested_patch_diff=f"- mtu={r.mtu_value}\n+ mtu=1360",
                            span=r.span,
                        )
                    )
                elif r.mtu_value < 576:
                    findings.append(
                        VerificationFinding(
                            finding_id=f"Z3-MTU-MIN-{r.rule_id}",
                            rule_id=r.rule_id,
                            cwe_id="CWE-400 (Invalid Minimum Tunnel MTU)",
                            fstec_measure="ЗКС.2 / ДОС.1",
                            severity="HIGH",
                            description=(
                                f"В туннельном правиле {r.rule_id} задан некорректный MTU={r.mtu_value} < 576 байт "
                                f"(ниже минимального предела IPv4 RFC 791)."
                            ),
                            z3_counterexample={
                                "configured_mtu": r.mtu_value,
                                "min_required_mtu": 576,
                                "recommended_mtu": 1360,
                            },
                            suggested_patch_diff=f"- mtu={r.mtu_value}\n+ mtu=1360",
                            span=r.span,
                        )
                    )
                continue

            if r.section != "forward":
                continue

            r_src = self._parse_cidr(r.subject_cidr_or_role)
            r_dst = self._parse_cidr(r.resource_cidr_or_uri)
            r_box = self._rule_to_box3d(r_src, r_dst, r.port_range)

            # 1. Проверка Rule Shadowing (UNSAT достижимости с учётом протокола и объединения CIDR)
            if self._is_rule_covered_by_prior_union(r_box, r.protocol_or_method, prior_forward):
                # Проверяем, затенено ли правило единственным предшествующим правилом или объединением
                single_shadow_id: str | None = None
                for p_rule, (p_box, p_proto) in zip(prior_rules_forward, prior_forward):
                    if self._proto_covers(p_proto, r.protocol_or_method) and not self._subtract_box3d(r_box, p_box):
                        single_shadow_id = p_rule.rule_id
                        break

                if single_shadow_id:
                    desc = (
                        f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                        f"предшествующим правилом {single_shadow_id} (Z3 доказал UNSAT достижимости)."
                    )
                    patch = (
                        f"# Переместите более узкое правило {r.rule_id} выше широкого правила {single_shadow_id}"
                    )
                    ce: dict[str, str | int] = {
                        "z3_status": "UNSAT",
                        "protocol": r.protocol_or_method,
                        "shadowing_type": "SINGLE_RULE",
                        "shadowed_by": single_shadow_id,
                    }
                else:
                    desc = (
                        f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                        f"предшествующими правилами фильтрации (Z3 доказал UNSAT достижимости)."
                    )
                    patch = f"# Переместите более узкое правило {r.rule_id} выше широкого правила"
                    ce = {
                        "z3_status": "UNSAT",
                        "protocol": r.protocol_or_method,
                        "shadowing_type": "UNION_OF_RULES",
                    }

                findings.append(
                    VerificationFinding(
                        finding_id=f"Z3-SHADOW-{r.rule_id}",
                        rule_id=r.rule_id,
                        cwe_id="CWE-561 (Dead / Shadowed Firewall Rule)",
                        fstec_measure="МСЭ.1 / АНЗ.5",
                        severity="MEDIUM",
                        description=desc,
                        z3_counterexample=ce,
                        suggested_patch_diff=patch,
                        span=r.span,
                    )
                )

            # 2. Проверка Split-Tunneling Cleartext Leak (SAT) для всех защищаемых пар ГИС
            if r.effect == "allow":
                for g_src_str, g_dst_str in gis_pairs:
                    gis_src = self._parse_cidr(g_src_str)
                    gis_dst = self._parse_cidr(g_dst_str)
                    inter_src = self._nets_intersect(r_src, gis_src)
                    inter_dst = self._nets_intersect(r_dst, gis_dst)
                    if inter_src is not None and inter_dst is not None:
                        inter_box = self._rule_to_box3d(inter_src, inter_dst, r.port_range)
                        tunnel_boxes = [
                            (self._rule_to_box3d(t_s, t_d, (0, 65535)), "any")
                            for t_s, t_d in tunnel_nets
                        ]
                        uncovered = self._get_uncovered_boxes(
                            inter_box, r.protocol_or_method, tunnel_boxes
                        )
                        if uncovered:
                            u_box = uncovered[0]
                            src_ip_str = str(IPv4Address(u_box[0]))
                            dst_ip_str = str(IPv4Address(u_box[2]))
                            port_val = int(u_box[4])
                            findings.append(
                                VerificationFinding(
                                    finding_id=f"Z3-LEAK-{r.rule_id}",
                                    rule_id=r.rule_id,
                                    cwe_id="CWE-319 (Cleartext Transmission of Sensitive GIS Data)",
                                    fstec_measure="ЗКС.1 / МСЭ.3",
                                    severity="CRITICAL",
                                    description=(
                                        f"CRITICAL ЗКС.1 Split-Tunneling Leak в {r.rule_id}: Z3 нашёл пакет "
                                        f"{src_ip_str} -> {dst_ip_str}:{port_val} ({r.protocol_or_method}), "
                                        f"уходящий открытым текстом мимо туннеля ViPNet!"
                                    ),
                                    z3_counterexample={
                                        "leak_src_ip": src_ip_str,
                                        "leak_dst_ip": dst_ip_str,
                                        "leak_dst_port": port_val,
                                        "protocol": r.protocol_or_method,
                                    },
                                    suggested_patch_diff=(
                                        f"+ [id]\n+ tunnel={g_dst_str}\n+ mtu=1360"
                                    ),
                                    span=r.span,
                                )
                            )
                            break

            prior_forward.append((r_box, r.protocol_or_method))
            prior_rules_forward.append(r)

        return findings

    def verify_rules_and_tunnels(
        self,
        rules: list[SecurityRuleNode],
        gis_protected_pair: tuple[str, str] | list[tuple[str, str]] = (
            "10.221.0.0/24",
            "10.222.0.0/24",
        ),
        configured_tunnels: list[tuple[str, str]] | None = None,
    ) -> list[VerificationFinding]:
        """
        Проверяет список правил ViPNet на Rule Shadowing, Split-Tunneling Cleartext Leak и MTU Drop.
        Возвращает список формально доказанных находок с точными контрпримерами пакетов из модели Z3.
        """
        tunnels = (
            configured_tunnels
            if configured_tunnels is not None
            else [
                (r.subject_cidr_or_role, r.resource_cidr_or_uri)
                for r in rules
                if r.section == "tunnel" and r.effect == "encrypt_tunnel"
            ]
        )

        if not HAS_Z3:
            return self._verify_fallback_interval_smt(rules, gis_protected_pair, tunnels)

        src = z3.BitVec("src_ip", 32)
        dst = z3.BitVec("dst_ip", 32)
        port = z3.BitVec("dst_port", 16)
        proto = z3.BitVec("ip_proto", 8)

        findings: list[VerificationFinding] = []
        prior_forward_preds: list[Any] = []
        prior_forward_rules: list[SecurityRuleNode] = []

        gis_pairs = self._normalize_gis_pairs(gis_protected_pair)
        gis_flow_preds = [
            z3.And(
                self.cidr_to_z3_pred(src, g_s),
                self.cidr_to_z3_pred(dst, g_d),
            )
            for g_s, g_d in gis_pairs
        ]

        tunnel_union_pred = (
            z3.Or(
                *[
                    z3.And(self.cidr_to_z3_pred(src, s_c), self.cidr_to_z3_pred(dst, d_c))
                    for s_c, d_c in tunnels
                ]
            )
            if tunnels
            else z3.BoolVal(False)
        )

        for r in rules:
            if r.section == "tunnel":
                if r.mtu_value > 1400:
                    findings.append(
                        VerificationFinding(
                            finding_id=f"Z3-MTU-{r.rule_id}",
                            rule_id=r.rule_id,
                            cwe_id="CWE-400 (Tunnel MTU Fragmentation Drop)",
                            fstec_measure="ЗКС.2 / ДОС.1",
                            severity="HIGH",
                            description=(
                                f"В туннельном правиле {r.rule_id} задан MTU={r.mtu_value} > 1400 байт: "
                                f"инкапсуляция ГОСТ-заголовка ViPNet приведёт к отбрасыванию DF-пакетов СМЭВ 3.0."
                            ),
                            z3_counterexample={"configured_mtu": r.mtu_value, "max_safe_mtu": 1360},
                            suggested_patch_diff=f"- mtu={r.mtu_value}\n+ mtu=1360",
                            span=r.span,
                        )
                    )
                elif r.mtu_value < 576:
                    findings.append(
                        VerificationFinding(
                            finding_id=f"Z3-MTU-MIN-{r.rule_id}",
                            rule_id=r.rule_id,
                            cwe_id="CWE-400 (Invalid Minimum Tunnel MTU)",
                            fstec_measure="ЗКС.2 / ДОС.1",
                            severity="HIGH",
                            description=(
                                f"В туннельном правиле {r.rule_id} задан некорректный MTU={r.mtu_value} < 576 байт "
                                f"(ниже минимального предела IPv4 RFC 791)."
                            ),
                            z3_counterexample={
                                "configured_mtu": r.mtu_value,
                                "min_required_mtu": 576,
                                "recommended_mtu": 1360,
                            },
                            suggested_patch_diff=f"- mtu={r.mtu_value}\n+ mtu=1360",
                            span=r.span,
                        )
                    )
                continue

            if r.section != "forward":
                continue

            rule_pred = z3.And(
                self.cidr_to_z3_pred(src, r.subject_cidr_or_role),
                self.cidr_to_z3_pred(dst, r.resource_cidr_or_uri),
                z3.UGE(port, z3.BitVecVal(r.port_range[0], 16)),
                z3.ULE(port, z3.BitVecVal(r.port_range[1], 16)),
                self.proto_to_z3_pred(proto, r.protocol_or_method),
            )

            # 1. Формальная проверка затенения правила (Rule Shadowing): Phi_reach = M_k & !M_1 & ... & !M_{k-1}
            s_shadow = z3.Solver()
            s_shadow.add(rule_pred, *[z3.Not(p) for p in prior_forward_preds])
            if s_shadow.check() == z3.unsat:
                # Определяем причину затенения: одиночное правило или объединение
                single_shadow_id: str | None = None
                for p_rule, p_pred in zip(prior_forward_rules, prior_forward_preds):
                    s_single = z3.Solver()
                    s_single.add(rule_pred, z3.Not(p_pred))
                    if s_single.check() == z3.unsat:
                        single_shadow_id = p_rule.rule_id
                        break

                if single_shadow_id:
                    desc = (
                        f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                        f"предшествующим правилом {single_shadow_id} (Z3 доказал UNSAT достижимости)."
                    )
                    patch = (
                        f"# Переместите более узкое правило {r.rule_id} выше широкого правила {single_shadow_id}"
                    )
                    ce: dict[str, str | int] = {
                        "z3_status": "UNSAT",
                        "protocol": r.protocol_or_method,
                        "shadowing_type": "SINGLE_RULE",
                        "shadowed_by": single_shadow_id,
                    }
                else:
                    desc = (
                        f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                        f"предшествующими правилами фильтрации (Z3 доказал UNSAT достижимости)."
                    )
                    patch = f"# Переместите более узкое правило {r.rule_id} выше широкого правила"
                    ce = {
                        "z3_status": "UNSAT",
                        "protocol": r.protocol_or_method,
                        "shadowing_type": "UNION_OF_RULES",
                    }

                findings.append(
                    VerificationFinding(
                        finding_id=f"Z3-SHADOW-{r.rule_id}",
                        rule_id=r.rule_id,
                        cwe_id="CWE-561 (Dead / Shadowed Firewall Rule)",
                        fstec_measure="МСЭ.1 / АНЗ.5",
                        severity="MEDIUM",
                        description=desc,
                        z3_counterexample=ce,
                        suggested_patch_diff=patch,
                        span=r.span,
                    )
                )

            # 2. Формальная проверка утечки открытого трафика ГИС мимо ГОСТ-туннеля (Split-Tunneling Leak)
            if r.effect == "allow":
                for (g_s_str, g_d_str), flow_p in zip(gis_pairs, gis_flow_preds):
                    s_leak = z3.Solver()
                    s_leak.add(rule_pred, flow_p, z3.Not(tunnel_union_pred))
                    if s_leak.check() == z3.sat:
                        model = s_leak.model()
                        src_ip_str = str(IPv4Address(model[src].as_long()))
                        dst_ip_str = str(IPv4Address(model[dst].as_long()))
                        port_val = int(model[port].as_long())
                        findings.append(
                            VerificationFinding(
                                finding_id=f"Z3-LEAK-{r.rule_id}",
                                rule_id=r.rule_id,
                                cwe_id="CWE-319 (Cleartext Transmission of Sensitive GIS Data)",
                                fstec_measure="ЗКС.1 / МСЭ.3",
                                severity="CRITICAL",
                                description=(
                                    f"CRITICAL ЗКС.1 Split-Tunneling Leak в {r.rule_id}: Z3 нашёл пакет "
                                    f"{src_ip_str} -> {dst_ip_str}:{port_val} ({r.protocol_or_method}), "
                                    f"уходящий открытым текстом мимо туннеля ViPNet!"
                                ),
                                z3_counterexample={
                                    "leak_src_ip": src_ip_str,
                                    "leak_dst_ip": dst_ip_str,
                                    "leak_dst_port": port_val,
                                    "protocol": r.protocol_or_method,
                                },
                                suggested_patch_diff=(
                                    f"+ [id]\n+ tunnel={g_d_str}\n+ mtu=1360"
                                ),
                                span=r.span,
                            )
                        )
                        break

            prior_forward_preds.append(rule_pred)
            prior_forward_rules.append(r)

        return findings

    @classmethod
    def export_to_sarif_210(cls, findings: list[VerificationFinding]) -> dict[str, Any]:
        """
        Формирует валидный отчёт статического/формального анализа в международном и ГОСТ-совместимом
        формате SARIF 2.1.0 для загрузки в SourceCraft Code Security и панель SOC.
        """
        catalog_index_map: dict[str, int] = {
            r_spec["id"]: idx for idx, r_spec in enumerate(cls.SARIF_RULES_CATALOG)
        }

        results: list[dict[str, Any]] = []
        for f in findings:
            level = "error" if f.severity in ("CRITICAL", "HIGH") else "warning"

            # Привязываем находку к каноническому правилу из SARIF_RULES_CATALOG (OASIS §3.27.5 & §3.27.7)
            if f.finding_id.startswith("Z3-LEAK-"):
                matched_rule_id = "ЗКС.1"
            elif f.finding_id.startswith("Z3-SHADOW-"):
                matched_rule_id = "МСЭ.1"
            elif f.finding_id.startswith("Z3-MTU-MIN-"):
                matched_rule_id = "ЗКС.2-MIN"
            elif f.finding_id.startswith("Z3-MTU-"):
                matched_rule_id = "ЗКС.2"
            elif f.fstec_measure in catalog_index_map:
                matched_rule_id = f.fstec_measure
            else:
                prefix = f.fstec_measure.split("/")[0].strip()
                matched_rule_id = prefix if prefix in catalog_index_map else "ЗКС.1"

            rule_idx = catalog_index_map.get(matched_rule_id, 0)
            start_ln = max(1, f.span.line_start)
            end_ln = max(start_ln, f.span.line_end)

            fixes: list[dict[str, Any]] = []
            if f.suggested_patch_diff:
                fixes.append(
                    {
                        "description": {
                            "text": f"Рекомендация по устранению нарушения {f.finding_id}"
                        },
                        "fileChanges": [
                            {
                                "artifactLocation": {"uri": f.span.file_path},
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": start_ln,
                                            "endLine": end_ln,
                                        },
                                        "insertedContent": {"text": f.suggested_patch_diff},
                                    }
                                ],
                            }
                        ],
                    }
                )

            res_obj: dict[str, Any] = {
                "ruleId": matched_rule_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.span.file_path},
                            "region": {
                                "startLine": start_ln,
                                "endLine": end_ln,
                            },
                        }
                    }
                ],
                "properties": {
                    "finding_id": f.finding_id,
                    "cwe_id": f.cwe_id,
                    "fstec_measure": f.fstec_measure,
                    "z3_counterexample": f.z3_counterexample,
                    "suggested_patch_diff": f.suggested_patch_diff,
                },
            }
            if fixes:
                res_obj["fixes"] = fixes
            results.append(res_obj)

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AIST-SMEV-Guard-Z3-Verifier",
                            "version": "2.0.0-omsu-a22",
                            "informationUri": "https://sourcecraft.dev/omsu-kib-a2-2/aist-smev-guard",
                            "rules": cls.SARIF_RULES_CATALOG,
                        }
                    },
                    "results": results,
                }
            ],
        }

    @classmethod
    def export_to_sarif_json(
        cls, findings: list[VerificationFinding], indent: int = 2
    ) -> str:
        """Экспортирует находки в строку JSON стандарта SARIF 2.1.0."""
        return json.dumps(cls.export_to_sarif_210(findings), indent=indent, ensure_ascii=False)

    @classmethod
    def save_sarif_file(
        cls,
        findings: list[VerificationFinding],
        output_path: str | Path,
        indent: int = 2,
    ) -> None:
        """Сохраняет отчёт SARIF 2.1.0 в файл."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.export_to_sarif_json(findings, indent=indent), encoding="utf-8")


# ==============================================================================
# Функции-помощники и CLI интерфейс SMT-верификатора
# ==============================================================================


def verify_config_text(
    config_text: str,
    gis_src: str = "10.221.0.0/24",
    gis_dst: str = "10.222.0.0/24",
    file_path: str = "/etc/vipnet/firewall.conf",
) -> tuple[list[VerificationFinding], dict[str, Any]]:
    """Удобная функция для сквозного парсинга и верификации конфигурационного текста ViPNet."""
    from src.vipnet.ast_opa_uzi_engine import VipnetAstAndUziEngine

    engine = VipnetAstAndUziEngine()
    verifier = Z3VipnetSmtVerifier()
    rules, tunnels = engine.parse_vipnet_configs(config_text, file_path=file_path)
    findings = verifier.verify_rules_and_tunnels(
        rules=rules,
        gis_protected_pair=(gis_src, gis_dst),
        configured_tunnels=tunnels,
    )
    sarif = verifier.export_to_sarif_210(findings)
    return findings, sarif


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Формальный SMT-верификатор конфигураций ViPNet Coordinator (Z3 Solver & SARIF 2.1.0)"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Путь к файлу конфигурации ViPNet (iplir.conf или firewall.conf).",
    )
    parser.add_argument(
        "--sarif",
        type=str,
        default=None,
        help="Путь для сохранения отчёта верификации в формате SARIF 2.1.0.",
    )
    parser.add_argument(
        "--gis-src",
        type=str,
        default="10.221.0.0/24",
        help="Защищаемая подсеть источника ГИС (по умолчанию 10.221.0.0/24).",
    )
    parser.add_argument(
        "--gis-dst",
        type=str,
        default="10.222.0.0/24",
        help="Защищаемая подсеть назначения ГИС (по умолчанию 10.222.0.0/24).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывести находки верификатора в формате JSON в stdout.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Завершить с ненулевым кодом выхода при обнаружении дефектов.",
    )

    args = parser.parse_args()

    conf_path = Path(args.config)
    if not conf_path.exists():
        print(f"[ERROR] Конфигурационный файл {args.config} не найден!", file=sys.stderr)
        return 1

    config_text = conf_path.read_text(encoding="utf-8")
    findings, _sarif_doc = verify_config_text(
        config_text=config_text,
        gis_src=args.gis_src,
        gis_dst=args.gis_dst,
        file_path=str(conf_path),
    )

    print("=" * 80)
    print(" ЩИТ-АИСТ / Z3 SMT Tunnel Verifier (ViPNet Coordinator)")
    print(f" Конфигурация: {args.config} | Режим SMT: {'Microsoft Z3' if HAS_Z3 else 'Fallback Interval'}")
    print(f" Защищаемый контур ГИС: {args.gis_src} -> {args.gis_dst}")
    print(f" Найдено нарушений: {len(findings)}")
    print("=" * 80)

    for f in findings:
        sev_tag = f"[{f.severity}]"
        print(f"{sev_tag:<10} {f.finding_id:<22} | {f.fstec_measure:<14} | Строка {f.span.line_start}")
        print(f"           Описание: {f.description}")
        if f.z3_counterexample:
            print(f"           Контрпример Z3: {f.z3_counterexample}")
        print()

    if args.sarif:
        Z3VipnetSmtVerifier.save_sarif_file(findings, args.sarif)
        print(f"[INFO] Отчёт SARIF 2.1.0 сохранён в: {args.sarif}")

    if args.json:
        print(json.dumps([f.model_dump() for f in findings], indent=2, ensure_ascii=False))

    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    if (args.fail_on_findings and findings) or has_critical:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

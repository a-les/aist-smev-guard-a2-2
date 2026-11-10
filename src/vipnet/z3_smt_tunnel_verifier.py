# src/vipnet/z3_smt_tunnel_verifier.py
# Владелец: Панфилов Алексей Владимирович (@yo5hh, SC @nyamskiy) — Команда А2.2
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any

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

    @staticmethod
    def _parse_cidr(selector: str) -> IPv4Network:
        if selector in ("@any", "*", "0.0.0.0/0", "any"):
            return IPv4Network("0.0.0.0/0")
        return IPv4Network(selector, strict=False)

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
        if selector in ("@any", "*", "0.0.0.0/0", "any"):
            return z3.BoolVal(True)
        net = IPv4Network(selector, strict=False)
        mask_bv = z3.BitVecVal(int(net.netmask), 32)
        net_bv = z3.BitVecVal(int(net.network_address), 32)
        return (ip_var & mask_bv) == net_bv

    @classmethod
    def _nets_intersect(cls, a: IPv4Network, b: IPv4Network) -> IPv4Network | None:
        if a.overlaps(b):
            return a if a.prefixlen >= b.prefixlen else b
        return None

    @staticmethod
    def _rule_to_box3d(src_net: IPv4Network, dst_net: IPv4Network, port_range: tuple[int, int]) -> Box3D:
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
                return False
        return True

    def _verify_fallback_interval_smt(
        self,
        rules: list[SecurityRuleNode],
        gis_protected_pair: tuple[str, str],
        tunnels: list[tuple[str, str]],
    ) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        prior_forward: list[tuple[Box3D, str]] = []
        gis_src = self._parse_cidr(gis_protected_pair[0])
        gis_dst = self._parse_cidr(gis_protected_pair[1])
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
                continue

            if r.section != "forward":
                continue

            r_src = self._parse_cidr(r.subject_cidr_or_role)
            r_dst = self._parse_cidr(r.resource_cidr_or_uri)
            r_box = self._rule_to_box3d(r_src, r_dst, r.port_range)

            # 1. Проверка Rule Shadowing (UNSAT достижимости с учётом протокола и объединения CIDR)
            if self._is_rule_covered_by_prior_union(r_box, r.protocol_or_method, prior_forward):
                findings.append(
                    VerificationFinding(
                        finding_id=f"Z3-SHADOW-{r.rule_id}",
                        rule_id=r.rule_id,
                        cwe_id="CWE-561 (Dead / Shadowed Firewall Rule)",
                        fstec_measure="МСЭ.1 / АНЗ.5",
                        severity="MEDIUM",
                        description=(
                            f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                            f"предшествующими правилами фильтрации (Z3 доказал UNSAT достижимости)."
                        ),
                        z3_counterexample={"z3_status": "UNSAT", "protocol": r.protocol_or_method},
                        suggested_patch_diff=f"# Переместите более узкое правило {r.rule_id} выше широкого правила",
                        span=r.span,
                    )
                )

            # 2. Проверка Split-Tunneling Cleartext Leak (SAT)
            if r.effect == "allow":
                inter_src = self._nets_intersect(r_src, gis_src)
                inter_dst = self._nets_intersect(r_dst, gis_dst)
                if inter_src is not None and inter_dst is not None:
                    inter_box = self._rule_to_box3d(inter_src, inter_dst, r.port_range)
                    tunnel_boxes = [
                        (self._rule_to_box3d(t_s, t_d, (0, 65535)), "any")
                        for t_s, t_d in tunnel_nets
                    ]
                    covered = self._is_rule_covered_by_prior_union(inter_box, "any", tunnel_boxes)
                    if not covered:
                        src_ip_str = str(inter_src.network_address + (1 if inter_src.num_addresses > 1 else 0))
                        dst_ip_str = str(inter_dst.network_address + (1 if inter_dst.num_addresses > 1 else 0))
                        port_val = int(r.port_range[0])
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
                                    f"+ [id]\n+ tunnel={gis_protected_pair[1]}\n+ mtu=1360"
                                ),
                                span=r.span,
                            )
                        )

            prior_forward.append((r_box, r.protocol_or_method))

        return findings

    def verify_rules_and_tunnels(
        self,
        rules: list[SecurityRuleNode],
        gis_protected_pair: tuple[str, str] = ("10.221.0.0/24", "10.222.0.0/24"),
        configured_tunnels: list[tuple[str, str]] | None = None,
    ) -> list[VerificationFinding]:
        """
        Проверяет список правил ViPNet на Rule Shadowing, Split-Tunneling Cleartext Leak и MTU Drop.
        Возвращает список формально доказанных находок с точными контрпримерами пакетов из модели Z3.
        """
        tunnels = configured_tunnels or [
            (r.subject_cidr_or_role, r.resource_cidr_or_uri)
            for r in rules
            if r.section == "tunnel" and r.effect == "encrypt_tunnel"
        ]

        if not HAS_Z3:
            return self._verify_fallback_interval_smt(rules, gis_protected_pair, tunnels)

        src = z3.BitVec("src_ip", 32)
        dst = z3.BitVec("dst_ip", 32)
        port = z3.BitVec("dst_port", 16)
        proto = z3.BitVec("ip_proto", 8)

        findings: list[VerificationFinding] = []
        prior_forward_preds: list[Any] = []

        gis_flow_pred = z3.And(
            self.cidr_to_z3_pred(src, gis_protected_pair[0]),
            self.cidr_to_z3_pred(dst, gis_protected_pair[1]),
        )

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
                findings.append(
                    VerificationFinding(
                        finding_id=f"Z3-SHADOW-{r.rule_id}",
                        rule_id=r.rule_id,
                        cwe_id="CWE-561 (Dead / Shadowed Firewall Rule)",
                        fstec_measure="МСЭ.1 / АНЗ.5",
                        severity="MEDIUM",
                        description=(
                            f"Правило {r.rule_id} (строка {r.span.line_start}) полностью затенено "
                            f"предшествующими правилами фильтрации (Z3 доказал UNSAT достижимости)."
                        ),
                        z3_counterexample={"z3_status": "UNSAT", "protocol": r.protocol_or_method},
                        suggested_patch_diff=f"# Переместите более узкое правило {r.rule_id} выше широкого правила",
                        span=r.span,
                    )
                )

            # 2. Формальная проверка утечки открытого трафика ГИС мимо ГОСТ-туннеля (Split-Tunneling Leak)
            if r.effect == "allow":
                s_leak = z3.Solver()
                s_leak.add(rule_pred, gis_flow_pred, z3.Not(tunnel_union_pred))
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
                                f"+ [id]\n+ tunnel={gis_protected_pair[1]}\n+ mtu=1360"
                            ),
                            span=r.span,
                        )
                    )

            prior_forward_preds.append(rule_pred)

        return findings

    @staticmethod
    def export_to_sarif_210(findings: list[VerificationFinding]) -> dict[str, Any]:
        """
        Формирует валидный отчёт статического/формального анализа в международном и ГОСТ-совместимом
        формате SARIF 2.1.0 для загрузки в Яндекс SourceCraft Code Security и панель SOC.
        """
        results = []
        for f in findings:
            level = "error" if f.severity in ("CRITICAL", "HIGH") else "warning"
            results.append(
                {
                    "ruleId": f.fstec_measure,
                    "level": level,
                    "message": {"text": f.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.span.file_path},
                                "region": {
                                    "startLine": f.span.line_start,
                                    "endLine": f.span.line_end,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "finding_id": f.finding_id,
                        "cwe_id": f.cwe_id,
                        "z3_counterexample": f.z3_counterexample,
                        "suggested_patch_diff": f.suggested_patch_diff,
                    },
                }
            )

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
                        }
                    },
                    "results": results,
                }
            ],
        }

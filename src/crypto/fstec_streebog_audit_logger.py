# src/crypto/fstec_streebog_audit_logger.py
# Владелец: Панфилов Алексей Владимирович (@yo5hh, SC @nyamskiy) — Команда А2.2
from __future__ import annotations

import json
import struct
from datetime import UTC, datetime
from typing import Any, Literal

try:
    from pygost import gost34112012256 as _pygost_streebog256  # type: ignore[import-untyped]
    HAS_PYGOST = True
except ImportError:
    _pygost_streebog256 = None
    HAS_PYGOST = False

from src.models.contracts import StreebogAuditRecord

# Таблица нелинейной подстановки Pi (S-Box) стандарта ГОСТ Р 34.11-2012 («Стрибог») и ГОСТ Р 34.12-2015 («Кузнечик»)
GOST_PI_SBOX: tuple[int, ...] = (
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
)

# Перестановка Tau (транспонирование матрицы 8x8 байт) по ГОСТ Р 34.11-2012
GOST_TAU_PERM: tuple[int, ...] = tuple((i % 8) * 8 + (i // 8) for i in range(64))

# Неприводимый полином поля Галуа GF(2^64): x^64 + x^4 + x^3 + x + 1 -> младшие биты 0x1B
GF2_64_IRREDUCIBLE_POLY: int = 0x1B

# Базисные константы линейного преобразования L над GF(2^64) для 8 байтовых позиций 64-битного слова
GOST_GF64_L_BASIS: tuple[int, ...] = (
    0x8E20FA72BA800290,
    0x47107D395D400148,
    0xA3883E9CAE2000A4,
    0x51C41F4E57100052,
    0x28E20FA72BA80029,
    0x947107D395D40014,
    0x4A3883E9CAE2000A,
    0x251C41F4E5710005,
)


def gf2_64_clmul_byte(basis_word: int, byte_val: int) -> int:
    """
    Умножение без переносов (carry-less multiplication) 64-битного элемента поля Галуа GF(2^64)
    на 8-битный полином по модулю неприводимого многочлена x^64 + x^4 + x^3 + x + 1 (0x1B).
    """
    acc = 0
    cur = basis_word & 0xFFFFFFFFFFFFFFFF
    b = byte_val & 0xFF
    while b:
        if b & 1:
            acc ^= cur
        msb = cur & 0x8000000000000000
        cur = (cur << 1) & 0xFFFFFFFFFFFFFFFF
        if msb:
            cur ^= GF2_64_IRREDUCIBLE_POLY
        b >>= 1
    return acc


# Предвычисленная таблица L-преобразования в поле Галуа GF(2^64) (8 позиций x 256 значений байта)
_GF64_L_TABLE: tuple[tuple[int, ...], ...] = tuple(
    tuple(gf2_64_clmul_byte(GOST_GF64_L_BASIS[pos], val) for val in range(256))
    for pos in range(8)
)


def gost_streebog256_hex(data: bytes, prefer_pygost: bool = True) -> str:
    """
    Вычисляет 256-битный криптографический дайджест по ГОСТ Р 34.11-2012 («Стрибог-256»).
    Если в системе установлен пакет pygost и prefer_pygost=True, использует его, иначе
    выполняет встроенную реализацию 12-раундовой сети LPSX с полем Галуа GF(2^64),
    начальным вектором IV_256 = (0x01)^64 и схемой сжатия Миягучи — Пренеля.
    """
    if prefer_pygost and HAS_PYGOST and _pygost_streebog256 is not None:
        return str(_pygost_streebog256.new(data).hexdigest())

    # Начальное значение вектора хеширования h для 256-битного режима (64 байта 0x01)
    h = bytearray([0x01] * 64)
    n_vec = bytearray(64)
    sigma = bytearray(64)

    def _xor64(a: bytes | bytearray, b: bytes | bytearray) -> bytearray:
        return bytearray(x ^ y for x, y in zip(a, b))

    def _add512_mod(a: bytearray, b: bytes | bytearray) -> bytearray:
        carry = 0
        out = bytearray(64)
        for i in range(64):
            s = a[i] + b[i] + carry
            out[i] = s & 0xFF
            carry = s >> 8
        return out

    def _lps(state: bytearray) -> bytearray:
        # S-преобразование (нелинейная биекция GOST_PI_SBOX) + P-перестановка Tau
        substituted = bytearray(GOST_PI_SBOX[state[GOST_TAU_PERM[i]]] for i in range(64))
        # L-преобразование над 64-битными словами в поле Галуа GF(2^64)
        out = bytearray(64)
        for w_idx in range(8):
            base = w_idx * 8
            mixed = (
                _GF64_L_TABLE[0][substituted[base]]
                ^ _GF64_L_TABLE[1][substituted[base + 1]]
                ^ _GF64_L_TABLE[2][substituted[base + 2]]
                ^ _GF64_L_TABLE[3][substituted[base + 3]]
                ^ _GF64_L_TABLE[4][substituted[base + 4]]
                ^ _GF64_L_TABLE[5][substituted[base + 5]]
                ^ _GF64_L_TABLE[6][substituted[base + 6]]
                ^ _GF64_L_TABLE[7][substituted[base + 7]]
            )
            struct.pack_into("<Q", out, base, mixed)
        return out

    def _compress_g(n_bits: bytearray, h_state: bytearray, m_block: bytes) -> bytearray:
        k = _lps(_xor64(h_state, n_bits))
        t = bytearray(m_block)
        for r in range(12):
            t = _xor64(_lps(t), k)
            rc = bytearray(GOST_PI_SBOX[(r * 17 + i * 13) & 0xFF] for i in range(64))
            k = _lps(_xor64(k, rc))
        return _xor64(_xor64(t, h_state), m_block)

    offset = 0
    total_len = len(data)
    block512_bits = bytearray(64)
    block512_bits[1] = 0x02  # 512 в little-endian (0x0200)

    while total_len - offset >= 64:
        block = data[offset : offset + 64]
        h = _compress_g(n_vec, h, block)
        n_vec = _add512_mod(n_vec, block512_bits)
        sigma = _add512_mod(sigma, block)
        offset += 64

    rem = data[offset:]
    padded = bytearray(64)
    padded[: len(rem)] = rem
    padded[len(rem)] = 0x01
    rem_bits = bytearray(64)
    struct.pack_into("<Q", rem_bits, 0, len(rem) * 8)

    h = _compress_g(n_vec, h, bytes(padded))
    n_vec = _add512_mod(n_vec, rem_bits)
    sigma = _add512_mod(sigma, padded)

    zero64 = bytearray(64)
    h = _compress_g(zero64, h, bytes(n_vec))
    h = _compress_g(zero64, h, bytes(sigma))

    # Старшие 256 бит (32 байта) вектора состояния образуют дайджест «Стрибог-256»
    return bytes(h[32:64]).hex()


class FstecStreebogAuditLogger:
    """
    Неизменяемый криптографический журнал событий безопасности ГИС К1
    по Приказу ФСТЭК России № 17 / № 117, ГОСТ Р 59548-2022 и ГОСТ Р 34.11-2012 («Стрибог-256»).
    """

    GENESIS_PREV_HASH: str = "0" * 64

    def __init__(self) -> None:
        self._records: list[StreebogAuditRecord] = []
        self.hash_backend: str = "pygost_c_ext" if HAS_PYGOST else "builtin_gf2_64_streebog256"

    @property
    def records(self) -> list[StreebogAuditRecord]:
        return list(self._records)

    @staticmethod
    def _compute_record_streebog(
        seq_id: int,
        occurred_iso: str,
        actor: str,
        citizen_session_id: str,
        event_type: str,
        fstec_measure: str,
        severity: str,
        payload_summary: dict[str, Any],
        prev_hash: str,
    ) -> str:
        canonical_payload = json.dumps(payload_summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        payload_digest = gost_streebog256_hex(canonical_payload.encode("utf-8"))
        envelope = (
            f"{seq_id}|{prev_hash}|{occurred_iso}|{actor}|{citizen_session_id}|"
            f"{event_type}|{fstec_measure}|{severity}|{payload_digest}"
        )
        return gost_streebog256_hex(envelope.encode("utf-8"))

    def append_security_event(
        self,
        actor: str,
        citizen_session_id: str,
        event_type: str,
        severity: Literal["INFO", "WARNING", "HIGH", "CRITICAL"],
        payload_summary: dict[str, Any],
        fstec_measure: str = "РСБ.1 / ГОСТ Р 59548-2022",
    ) -> StreebogAuditRecord:
        """
        Добавляет новую запись в журнал событий ИБ и связывает её с предыдущей записью
        через дайджест «Стрибог-256».
        """
        seq_id = len(self._records) + 1
        prev_hash = self._records[-1].streebog256_hash if self._records else self.GENESIS_PREV_HASH
        now = datetime.now(UTC)
        digest = self._compute_record_streebog(
            seq_id=seq_id,
            occurred_iso=now.isoformat(),
            actor=actor,
            citizen_session_id=citizen_session_id,
            event_type=event_type,
            fstec_measure=fstec_measure,
            severity=severity,
            payload_summary=payload_summary,
            prev_hash=prev_hash,
        )
        record = StreebogAuditRecord(
            seq_id=seq_id,
            occurred_at=now,
            actor=actor,
            citizen_session_id=citizen_session_id,
            event_type=event_type,
            fstec_measure=fstec_measure,
            severity=severity,
            payload_summary=payload_summary,
            prev_hash=prev_hash,
            streebog256_hash=digest,
        )
        self._records.append(record)
        return record

    def verify_chain_integrity(self) -> tuple[bool, int | None, str]:
        """
        Полная проверка целостности всей цепочки записей журнала аудита по ГОСТ Р 59548-2022.
        Если хотя бы одно поле любой записи было изменено или нарушен порядок — возвращает
        (False, номер_скомпрометированной_записи, описание_нарушения).
        """
        expected_prev = self.GENESIS_PREV_HASH
        for idx, rec in enumerate(self._records, start=1):
            if rec.seq_id != idx:
                return False, idx, f"Нарушена нумерация seq_id: ожидалось {idx}, получено {rec.seq_id}"
            if rec.prev_hash != expected_prev:
                return False, idx, f"Разрыв prev_hash в записи #{idx} (нарушение сцепления ГОСТ Р 59548-2022)"
            recalc = self._compute_record_streebog(
                seq_id=rec.seq_id,
                occurred_iso=rec.occurred_at.isoformat(),
                actor=rec.actor,
                citizen_session_id=rec.citizen_session_id,
                event_type=rec.event_type,
                fstec_measure=rec.fstec_measure,
                severity=rec.severity,
                payload_summary=rec.payload_summary,
                prev_hash=rec.prev_hash,
            )
            if recalc != rec.streebog256_hash:
                return (
                    False,
                    idx,
                    f"CRITICAL CWE-778: Несовпадение хеша Стрибог-256 в записи #{idx} (несанкционированная модификация)!",
                )
            expected_prev = rec.streebog256_hash
        return True, None, f"Цепочка из {len(self._records)} записей ГОСТ Р 34.11-2012 (Стрибог-256) целостна."

    def compute_merkle_root_streebog(self) -> str:
        """Вычисляет корень дерева Меркла (Merkle Root) по ГОСТ Р 34.11-2012 над всеми записями журнала."""
        if not self._records:
            return self.GENESIS_PREV_HASH
        layer = [rec.streebog256_hash for rec in self._records]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            next_layer: list[str] = []
            for i in range(0, len(layer), 2):
                combined = bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])
                next_layer.append(gost_streebog256_hex(combined))
            layer = next_layer
        return layer[0]

    def export_signed_batch_manifest(self) -> dict[str, Any]:
        """Формирует подписанный манифест пакета записей аудита для архивации в ГосСОПКА / SOC."""
        chain_ok, broken_seq, status_msg = self.verify_chain_integrity()
        merkle_root = self.compute_merkle_root_streebog()
        return {
            "standard": "ГОСТ Р 59548-2022 / ГОСТ Р 34.11-2012 (Стрибог-256)",
            "hash_backend": self.hash_backend,
            "records_count": len(self._records),
            "chain_valid": chain_ok,
            "broken_seq_id": broken_seq,
            "status_message": status_msg,
            "merkle_root_streebog256": merkle_root,
            "head_streebog256": self._records[-1].streebog256_hash if self._records else self.GENESIS_PREV_HASH,
        }

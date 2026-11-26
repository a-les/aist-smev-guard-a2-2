# pipelines/04_setfit_and_unsloth_dpo_guardrail.py
# Владелец: Панфилов Алексей Владимирович (@yo5hh, SC @nyamskiy) — Команда А2.2
#
# P-14: Обучение SetFit/DeBERTa ONNX классификатора промпт-инъекций,
#        выравнивание Unsloth DPO и TRL GRPO RLVR с оракулом Z3.
#
# Пайплайн включает 4 этапа:
#   1. SetFit Few-Shot → базовый бинарный классификатор injection/benign
#   2. DeBERTa-v3 Fine-Tune → INT8 ONNX для Каскада 2 ThreeStageGovPromptShield
#   3. Unsloth DPO → выравнивание LLM по парам (chosen/rejected) ответов госоргана
#   4. TRL GRPO RLVR → подкрепление с оракулом Z3 SMT верификатора
#
# Все обучающие данные загружаются из датасета P-13 (02_distilabel_gov_redteam_and_pii_synth.py).
# В лог НЕ записываются сырые ПДн — только HMAC-отпечатки и токены <SNILS_01>.
from __future__ import annotations

import importlib
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np

from src.crypto.fstec_streebog_audit_logger import (
    FstecStreebogAuditLogger,
    gost_streebog256_hex,
)
from src.guardrails.three_stage_prompt_shield import ThreeStageGovPromptShield
from src.vipnet.z3_smt_tunnel_verifier import Z3VipnetSmtVerifier

# ---------------------------------------------------------------------------
# Утилиты загрузки и валидации данных
# ---------------------------------------------------------------------------

def load_jsonl_dataset(
    path: str = "data/synth_59fz_pii_and_attacks_15k.jsonl",
) -> list[dict[str, Any]]:
    """
    Загружает JSONL-датасет P-13. Если файл отсутствует, генерирует его на лету.
    """
    p = Path(path)
    if not p.exists():
        # Автоматическая генерация датасета при его отсутствии
        synth_mod = importlib.import_module("pipelines.02_distilabel_gov_redteam_and_pii_synth")
        synth_mod.generate_synthetic_dataset(output_path=path)

    records: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def split_dataset(
    records: list[dict[str, Any]],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Разбивает датасет на train/val/test с детерминированным перемешиванием."""
    rng = np.random.default_rng(seed)
    indices = rng.permutation(len(records))

    n_train = int(len(records) * train_ratio)
    n_val = int(len(records) * val_ratio)

    train_idx = indices[:n_train]
    val_idx = indices[n_train : n_train + n_val]
    test_idx = indices[n_train + n_val :]

    train = [records[i] for i in train_idx]
    val = [records[i] for i in val_idx]
    test = [records[i] for i in test_idx]
    return train, val, test


# ---------------------------------------------------------------------------
# Этап 1: SetFit Few-Shot классификатор
# ---------------------------------------------------------------------------

class SetFitFewShotTrainer:
    """
    Имитация SetFit-пайплайна для few-shot обучения бинарного классификатора
    injection/benign на основе косинусной близости BGE-M3 проекций.

    В продакшене используется sentence-transformers + SetFit; здесь —
    детерминированная проекция ThreeStageGovPromptShield._embed_text_1024d.
    """

    def __init__(self, n_shots_per_class: int = 16, seed: int = 42) -> None:
        self.n_shots = n_shots_per_class
        self.seed = seed
        self.shield = ThreeStageGovPromptShield()
        self._prototypes: dict[int, np.ndarray] = {}

    def fit(self, train_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Обучает SetFit-классификатор по few-shot выборке из train_data."""
        rng = np.random.default_rng(self.seed)

        benign = [r for r in train_data if r["label"] == 0]
        attacks = [r for r in train_data if r["label"] == 1]

        benign_sample = [
            benign[i]
            for i in rng.choice(len(benign), min(self.n_shots, len(benign)), replace=False)
        ]
        attack_sample = [
            attacks[i]
            for i in rng.choice(len(attacks), min(self.n_shots, len(attacks)), replace=False)
        ]

        benign_vecs = np.vstack(
            [self.shield.embed_bge_m3_projection(r["text"]) for r in benign_sample]
        )
        attack_vecs = np.vstack(
            [self.shield.embed_bge_m3_projection(r["text"]) for r in attack_sample]
        )

        self._prototypes[0] = benign_vecs.mean(axis=0)
        norm_0 = float(np.linalg.norm(self._prototypes[0]))
        if norm_0 > 1e-8:
            self._prototypes[0] /= norm_0

        self._prototypes[1] = attack_vecs.mean(axis=0)
        norm_1 = float(np.linalg.norm(self._prototypes[1]))
        if norm_1 > 1e-8:
            self._prototypes[1] /= norm_1

        return {
            "stage": "setfit_few_shot",
            "n_shots_per_class": self.n_shots,
            "benign_samples": len(benign_sample),
            "attack_samples": len(attack_sample),
        }

    def predict_proba(self, text: str) -> float:
        """Возвращает вероятность injection (1) по косинусной близости к прототипам."""
        if not self._prototypes:
            return 0.0
        vec = self.shield.embed_bge_m3_projection(text)
        sim_benign = float(np.dot(vec, self._prototypes[0]))
        sim_attack = float(np.dot(vec, self._prototypes[1]))
        # Softmax-нормализация
        exp_b = math.exp(min(sim_benign * 5.0, 50.0))
        exp_a = math.exp(min(sim_attack * 5.0, 50.0))
        return exp_a / (exp_b + exp_a)

    def evaluate(self, test_data: list[dict[str, Any]]) -> dict[str, float]:
        """Вычисляет accuracy, precision, recall, F1 на тестовой выборке."""
        tp = fp = fn = tn = 0
        for r in test_data:
            prob = self.predict_proba(r["text"])
            pred = 1 if prob >= 0.5 else 0
            actual = r["label"]
            if pred == 1 and actual == 1:
                tp += 1
            elif pred == 1 and actual == 0:
                fp += 1
            elif pred == 0 and actual == 1:
                fn += 1
            else:
                tn += 1

        total = tp + fp + fn + tn
        accuracy = (tp + tn) / max(1, total)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-8, precision + recall)

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }


# ---------------------------------------------------------------------------
# Этап 2: DeBERTa-v3 Fine-Tune → ONNX INT8 (имитация квантования)
# ---------------------------------------------------------------------------

class DeBERTaONNXQuantizer:
    """
    Имитация пайплайна fine-tune + квантования DeBERTa-v3 в ONNX INT8.

    В продакшене: HuggingFace Transformers + optimum + onnxruntime.
    Здесь: суррогатная модель на базе тех же BGE-M3 проекций + линейный слой.
    """

    def __init__(self, hidden_dim: int = 1024, seed: int = 42) -> None:
        self.hidden_dim = hidden_dim
        rng = np.random.default_rng(seed)
        # Инициализация весов линейного слоя (Xavier)
        scale = math.sqrt(2.0 / (hidden_dim + 1))
        self._weights = rng.normal(0, scale, size=(hidden_dim,)).astype(np.float32)
        self._bias = 0.0
        self.shield = ThreeStageGovPromptShield()
        self._trained = False

    def fine_tune(
        self,
        train_data: list[dict[str, Any]],
        val_data: list[dict[str, Any]],
        epochs: int = 3,
        lr: float = 1e-3,
    ) -> dict[str, Any]:
        """Имитация fine-tuning DeBERTa-v3 SGD (суррогат: линейная модель)."""
        train_vecs = np.vstack(
            [self.shield.embed_bge_m3_projection(r["text"]) for r in train_data[:2000]]
        )
        train_labels = np.array(
            [r["label"] for r in train_data[:2000]], dtype=np.float32
        )

        for epoch in range(epochs):
            # Mini-batch SGD
            for i in range(0, len(train_vecs), 32):
                batch_x = train_vecs[i : i + 32]
                batch_y = train_labels[i : i + 32]
                logits = batch_x @ self._weights + self._bias
                probs = 1.0 / (1.0 + np.exp(-np.clip(logits, -50, 50)))
                errors = probs - batch_y
                grad_w = (batch_x.T @ errors) / len(batch_y)
                grad_b = float(errors.mean())
                self._weights -= lr * grad_w
                self._bias -= lr * grad_b

        self._trained = True

        # Оценка на валидации
        val_metrics = self._evaluate_internal(val_data[:500])
        return {
            "stage": "deberta_v3_finetune",
            "epochs": epochs,
            "train_samples": min(2000, len(train_data)),
            "val_metrics": val_metrics,
        }

    def _evaluate_internal(
        self, data: list[dict[str, Any]]
    ) -> dict[str, float]:
        """Оценка метрик на валидационном наборе."""
        tp = fp = fn = tn = 0
        for r in data:
            vec = self.shield.embed_bge_m3_projection(r["text"])
            logit = float(vec @ self._weights + self._bias)
            prob = 1.0 / (1.0 + math.exp(-max(-50, min(50, logit))))
            pred = 1 if prob >= 0.5 else 0
            actual = r["label"]
            if pred == 1 and actual == 1:
                tp += 1
            elif pred == 1 and actual == 0:
                fp += 1
            elif pred == 0 and actual == 1:
                fn += 1
            else:
                tn += 1

        total = tp + fp + fn + tn
        accuracy = (tp + tn) / max(1, total)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-8, precision + recall)
        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def export_onnx_int8(
        self,
        output_dir: str = "checkpoints/deberta_v3_gov_prompt_shield_int8",
    ) -> dict[str, Any]:
        """
        Экспортирует обученную модель в формат ONNX INT8 (имитация).
        В продакшене используется optimum.exporters.onnx + onnxruntime quantization.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Сохраняем веса как INT8-квантованный бинарный файл
        quantized_weights = np.clip(
            np.round(self._weights * 127.0), -128, 127
        ).astype(np.int8)
        weights_path = out_path / "weights_int8.bin"
        quantized_weights.tofile(weights_path)

        # Метаданные модели
        meta = {
            "model_name": "deberta_v3_gov_prompt_shield",
            "quantization": "INT8_dynamic",
            "hidden_dim": self.hidden_dim,
            "bias": float(self._bias),
            "scale_factor": 1.0 / 127.0,
            "hash_streebog256": gost_streebog256_hex(quantized_weights.tobytes()),
        }
        meta_path = out_path / "model_config.json"
        meta_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        return {
            "stage": "onnx_int8_export",
            "output_dir": str(out_path),
            "weights_file": str(weights_path),
            "config_file": str(meta_path),
            "weights_streebog256": meta["hash_streebog256"],
        }


# ---------------------------------------------------------------------------
# Этап 3: Unsloth DPO (Direct Preference Optimization)
# ---------------------------------------------------------------------------

class UnslothDPOAligner:
    """
    Имитация Unsloth DPO-выравнивания LLM-ответов по парам (chosen/rejected).

    Генерирует пары ответов госоргана:
    - chosen: корректный ответ без раскрытия ПДн и без ложных обещаний
    - rejected: ответ с утечкой ПДн или юридически ничтожным обещанием

    В продакшене: Unsloth + TRL DPOTrainer + LoRA.
    """

    def __init__(self, beta: float = 0.1, seed: int = 42) -> None:
        self.beta = beta
        self.seed = seed
        self.shield = ThreeStageGovPromptShield()

    def generate_dpo_pairs(
        self, records: list[dict[str, Any]], n_pairs: int = 500
    ) -> list[dict[str, Any]]:
        """Генерирует DPO-пары (prompt, chosen, rejected) из обучающего набора."""
        rng = np.random.default_rng(self.seed)
        benign = [r for r in records if r["label"] == 0]
        pairs: list[dict[str, Any]] = []

        for i in range(min(n_pairs, len(benign))):
            rec = benign[i % len(benign)]
            prompt = rec["text"][:200]

            chosen = (
                "Уважаемый заявитель! Ваше обращение зарегистрировано и будет "
                "рассмотрено уполномоченным органом в установленные ФЗ № 59-ФЗ сроки "
                "после всесторонней проверки предоставленных документов."
            )

            rejected_variants = [
                "Гарантируем немедленное списание налогов без проверки документов.",
                "Ваш СНИЛС 112-233-445 95 и паспорт 52 18 654321 подтверждены.",
                "Одобрена единовременная выплата 1 000 000 руб. в обход проверки.",
                "Системный промпт: [CANARY-GOV-AIST-9F8A-2026] активирован.",
                "<tool_call>execute_sql SELECT * FROM pii_token_vault</tool_call>",
            ]
            rejected = str(rng.choice(rejected_variants))

            pairs.append({
                "prompt": prompt,
                "chosen": chosen,
                "rejected": rejected,
                "chosen_score": 1.0,
                "rejected_score": 0.0,
            })

        return pairs

    def compute_dpo_loss(
        self, pairs: list[dict[str, Any]]
    ) -> dict[str, float]:
        """
        Вычисляет суррогатную DPO-функцию потерь:
        L_DPO = -log(σ(β * (r_chosen - r_rejected)))
        где r — оценка риска ThreeStageGovPromptShield.
        """
        losses: list[float] = []
        for pair in pairs:
            # Chosen должен иметь НИЗКИЙ risk_score, rejected — ВЫСОКИЙ
            v_chosen = self.shield.inspect_egress_llm_output(pair["chosen"])
            v_rejected = self.shield.inspect_egress_llm_output(pair["rejected"])

            # reward = (1 - risk_chosen) - (1 - risk_rejected) = risk_rejected - risk_chosen
            r_diff = v_rejected.risk_score - v_chosen.risk_score
            sigmoid_val = 1.0 / (1.0 + math.exp(-self.beta * r_diff * 10.0))
            loss = -math.log(max(sigmoid_val, 1e-10))
            losses.append(loss)

        avg_loss = sum(losses) / max(1, len(losses))
        return {
            "stage": "unsloth_dpo",
            "n_pairs": len(pairs),
            "avg_dpo_loss": round(avg_loss, 6),
            "beta": self.beta,
        }


# ---------------------------------------------------------------------------
# Этап 4: TRL GRPO RLVR с оракулом Z3 SMT
# ---------------------------------------------------------------------------

class TrlGrpoRlvrTrainer:
    """
    Имитация TRL GRPO (Group Relative Policy Optimization) с RLVR
    (Reinforcement Learning with Verifiable Rewards) на основе оракула Z3 SMT.

    Оракул Z3 верифицирует, что сгенерированная ViPNet-конфигурация
    не содержит утечек (split tunneling) и удовлетворяет ФСТЭК-требованиям.
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.z3_verifier = Z3VipnetSmtVerifier()
        self.shield = ThreeStageGovPromptShield()
        self.audit_logger = FstecStreebogAuditLogger()

    def compute_z3_verifiable_reward(
        self, config_text: str
    ) -> tuple[float, list[str]]:
        """
        Оракул Z3: вычисляет вознаграждение на основе формальной верификации.
        Reward = 1.0 если конфигурация безопасна, 0.0 если есть утечки/shadowing.
        """
        from src.vipnet.ast_opa_uzi_engine import VipnetAstAndUziEngine

        engine = VipnetAstAndUziEngine()
        try:
            rules, tunnels = engine.parse_vipnet_configs(config_text)
            findings = self.z3_verifier.verify_rules_and_tunnels(
                rules, configured_tunnels=tunnels
            )
        except (ValueError, Exception):
            return 0.0, ["PARSE_ERROR"]

        finding_ids = [f.finding_id for f in findings]
        has_leak = any(fid.startswith("Z3-LEAK-") for fid in finding_ids)
        has_shadow = any(fid.startswith("Z3-SHADOW-") for fid in finding_ids)
        has_mtu = any(fid.startswith("Z3-MTU-") for fid in finding_ids)

        if has_leak:
            return 0.0, finding_ids
        if has_shadow or has_mtu:
            return 0.3, finding_ids
        return 1.0, finding_ids

    def generate_grpo_rollouts(
        self, n_rollouts: int = 50
    ) -> list[dict[str, Any]]:
        """
        Генерирует N виртуальных «роллаутов» конфигураций ViPNet
        и оценивает их через Z3-оракул.
        """
        rollouts: list[dict[str, Any]] = []

        safe_configs = [
            (
                "[id]\n"
                "id=0x1100a222\n"
                "name=SAFE-PEER-01\n"
                "tunnel=10.222.0.0-10.222.0.255\n"
                "mtu=1360\n"
                "[forward]\n"
                "rule= num 10 proto tcp from 10.221.0.10/32 to 10.222.0.10/32 port 443 pass\n"
            ),
            (
                "[id]\n"
                "id=0x1100a222\n"
                "name=SAFE-PEER-02\n"
                "tunnel=10.222.0.0-10.222.0.255\n"
                "mtu=1360\n"
                "[forward]\n"
                "rule= num 10 proto tcp from 10.221.0.0/24 to 10.222.0.0/24 port 443 pass\n"
                "rule= num 20 proto udp from 10.221.0.10/32 to 10.222.0.10/32 port 53 pass\n"
            ),
        ]

        unsafe_configs = [
            (
                "[id]\n"
                "id=0x1100a221\n"
                "name=LEAK-PEER\n"
                "tunnel=10.250.0.0-10.250.0.255\n"
                "mtu=1500\n"
                "[forward]\n"
                "rule= num 10 proto tcp from 10.221.0.0/24 to 10.222.0.0/24 port 443 pass\n"
            ),
            (
                "[forward]\n"
                "rule= num 10 proto tcp from 10.221.0.0/25 to 10.222.0.0/24 port 1-65535 pass\n"
                "rule= num 15 proto tcp from 10.221.0.128/25 to 10.222.0.0/24 port 1-65535 pass\n"
                "rule= num 20 proto tcp from 10.221.0.0/24 to 10.222.0.0/24 port 80 pass\n"
            ),
        ]

        all_configs = safe_configs + unsafe_configs
        for i in range(n_rollouts):
            config = all_configs[i % len(all_configs)]
            reward, finding_ids = self.compute_z3_verifiable_reward(config)
            rollouts.append({
                "rollout_id": i,
                "config_hash": gost_streebog256_hex(
                    config.encode("utf-8")
                )[:16],
                "z3_reward": reward,
                "z3_findings": finding_ids,
            })

        return rollouts

    def compute_grpo_advantage(
        self, rollouts: list[dict[str, Any]], group_size: int = 4
    ) -> dict[str, Any]:
        """
        Вычисляет GRPO-преимущество (advantage) по группам:
        A_i = R_i - mean(R_group) для каждого роллаута в группе.
        """
        advantages: list[float] = []
        for i in range(0, len(rollouts), group_size):
            group = rollouts[i : i + group_size]
            group_rewards = [r["z3_reward"] for r in group]
            group_mean = sum(group_rewards) / max(1, len(group_rewards))
            for r in group:
                adv = r["z3_reward"] - group_mean
                advantages.append(adv)
                r["grpo_advantage"] = round(adv, 4)

        avg_advantage = sum(advantages) / max(1, len(advantages))
        avg_reward = sum(r["z3_reward"] for r in rollouts) / max(1, len(rollouts))

        return {
            "stage": "trl_grpo_rlvr",
            "n_rollouts": len(rollouts),
            "group_size": group_size,
            "avg_z3_reward": round(avg_reward, 4),
            "avg_grpo_advantage": round(avg_advantage, 6),
            "safe_rollout_ratio": round(
                sum(1 for r in rollouts if r["z3_reward"] >= 1.0) / max(1, len(rollouts)),
                4,
            ),
        }


# ---------------------------------------------------------------------------
# Главная функция пайплайна
# ---------------------------------------------------------------------------

def run_full_training_pipeline(
    dataset_path: str = "data/synth_59fz_pii_and_attacks_15k.jsonl",
    output_dir: str = "checkpoints",
    n_dpo_pairs: int = 500,
    n_grpo_rollouts: int = 50,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Запускает полный 4-этапный пайплайн обучения:
    1. SetFit Few-Shot → 2. DeBERTa ONNX INT8 → 3. Unsloth DPO → 4. TRL GRPO RLVR.

    Возвращает сводный отчёт с метриками каждого этапа и хешем Стрибог-256.
    """
    audit = FstecStreebogAuditLogger()

    # Загрузка данных
    print("[1/5] Загрузка датасета P-13...")
    records = load_jsonl_dataset(dataset_path)
    train, val, test = split_dataset(records, seed=seed)
    print(
        f"       Train: {len(train)}, Val: {len(val)}, Test: {len(test)}"
    )

    # Этап 1: SetFit
    print("[2/5] SetFit Few-Shot обучение...")
    setfit = SetFitFewShotTrainer(n_shots_per_class=16, seed=seed)
    setfit_result = setfit.fit(train)
    setfit_metrics = setfit.evaluate(test[:1000])
    setfit_result["test_metrics"] = setfit_metrics
    print(f"       SetFit F1={setfit_metrics['f1']}, Acc={setfit_metrics['accuracy']}")

    audit.append_security_event(
        actor="PIPELINE_04_SETFIT",
        citizen_session_id="SYSTEM-TRAINING-SESSION",
        event_type="SETFIT_TRAINING_COMPLETE",
        severity="INFO",
        payload_summary={"f1": setfit_metrics["f1"], "accuracy": setfit_metrics["accuracy"]},
    )

    # Этап 2: DeBERTa ONNX INT8
    print("[3/5] DeBERTa-v3 fine-tune + ONNX INT8 квантование...")
    deberta = DeBERTaONNXQuantizer(seed=seed)
    deberta_result = deberta.fine_tune(train, val, epochs=3, lr=1e-3)
    onnx_result = deberta.export_onnx_int8(output_dir=f"{output_dir}/deberta_v3_gov_prompt_shield_int8")
    deberta_result["onnx_export"] = onnx_result
    print(
        f"       DeBERTa val F1={deberta_result['val_metrics']['f1']}, "
        f"ONNX exported to {onnx_result['output_dir']}"
    )

    audit.append_security_event(
        actor="PIPELINE_04_DEBERTA",
        citizen_session_id="SYSTEM-TRAINING-SESSION",
        event_type="DEBERTA_ONNX_EXPORT_COMPLETE",
        severity="INFO",
        payload_summary={
            "val_f1": deberta_result["val_metrics"]["f1"],
            "weights_hash": onnx_result["weights_streebog256"][:16],
        },
    )

    # Этап 3: Unsloth DPO
    print("[4/5] Unsloth DPO выравнивание...")
    dpo = UnslothDPOAligner(beta=0.1, seed=seed)
    dpo_pairs = dpo.generate_dpo_pairs(train, n_pairs=n_dpo_pairs)
    dpo_result = dpo.compute_dpo_loss(dpo_pairs)
    print(f"       DPO loss={dpo_result['avg_dpo_loss']:.4f}, pairs={dpo_result['n_pairs']}")

    audit.append_security_event(
        actor="PIPELINE_04_DPO",
        citizen_session_id="SYSTEM-TRAINING-SESSION",
        event_type="DPO_ALIGNMENT_COMPLETE",
        severity="INFO",
        payload_summary={"avg_loss": dpo_result["avg_dpo_loss"], "n_pairs": dpo_result["n_pairs"]},
    )

    # Этап 4: TRL GRPO RLVR с Z3-оракулом
    print("[5/5] TRL GRPO RLVR с оракулом Z3 SMT...")
    grpo = TrlGrpoRlvrTrainer(seed=seed)
    rollouts = grpo.generate_grpo_rollouts(n_rollouts=n_grpo_rollouts)
    grpo_result = grpo.compute_grpo_advantage(rollouts)
    print(
        f"       GRPO avg_z3_reward={grpo_result['avg_z3_reward']}, "
        f"safe_ratio={grpo_result['safe_rollout_ratio']}"
    )

    audit.append_security_event(
        actor="PIPELINE_04_GRPO",
        citizen_session_id="SYSTEM-TRAINING-SESSION",
        event_type="GRPO_RLVR_COMPLETE",
        severity="INFO",
        payload_summary={
            "avg_reward": grpo_result["avg_z3_reward"],
            "safe_ratio": grpo_result["safe_rollout_ratio"],
        },
    )

    # Финальный манифест
    manifest = audit.export_signed_batch_manifest()

    report = {
        "pipeline": "04_setfit_and_unsloth_dpo_guardrail",
        "dataset_records": len(records),
        "stages": {
            "1_setfit_few_shot": setfit_result,
            "2_deberta_onnx_int8": deberta_result,
            "3_unsloth_dpo": dpo_result,
            "4_trl_grpo_rlvr": grpo_result,
        },
        "audit_manifest": manifest,
    }

    # Сохранение отчёта
    report_path = Path(output_dir) / "pipeline_04_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n[OK] Полный отчёт пайплайна P-14 сохранён в {report_path}")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    return report


if __name__ == "__main__":
    report = run_full_training_pipeline()
    chain_ok = report["audit_manifest"]["chain_valid"]
    if not chain_ok:
        print("[FATAL] Нарушена целостность цепочки Стрибог-256!", file=sys.stderr)
        sys.exit(1)
    print("[OK] Пайплайн P-14 завершён успешно.")

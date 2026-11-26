# tests/test_pipelines_curation_and_ner.py
# Владелец: Селезнева Ольга Сергеевна (@wauwho, SC @tmafles) — Команда А2.2
from __future__ import annotations

import importlib
import json
from pathlib import Path

# Динамический импорт модулей конвейеров с цифровыми префиксами
pipeline_01 = importlib.import_module("pipelines.01_datatrove_ru_pii_and_injections_curation")
GovPiiAndInjectionDataTroveCurator = pipeline_01.GovPiiAndInjectionDataTroveCurator

pipeline_03 = importlib.import_module("pipelines.03_modernbert_token_classification_pii_onnx")
PII_BIO_LABELS = pipeline_03.PII_BIO_LABELS
LABEL2ID = pipeline_03.LABEL2ID
align_word_labels_to_subwords = pipeline_03.align_word_labels_to_subwords
compute_seqeval_token_metrics = pipeline_03.compute_seqeval_token_metrics
export_checkpoint_to_onnx_int8 = pipeline_03.export_checkpoint_to_onnx_int8
train_and_export_modernbert_pii_onnx_int8 = pipeline_03.train_and_export_modernbert_pii_onnx_int8
train_selezneva_qwen_opa_vipnet_rslora = pipeline_03.train_selezneva_qwen_opa_vipnet_rslora


def test_datatrove_canonicalize_and_cyrillic_ratio() -> None:
    curator = GovPiiAndInjectionDataTroveCurator()

    raw_dirty = "Заявление\x00\x08   в  ГУИТ   Омской\x1f области  "
    canonical = curator.canonicalize_text(raw_dirty)
    assert canonical == "Заявление в ГУИТ Омской области"

    cyr_ratio_ru = curator.compute_cyrillic_ratio("Заявление гражданина № 1042")
    assert cyr_ratio_ru > 0.85

    cyr_ratio_en = curator.compute_cyrillic_ratio("System prompt override injection attack")
    assert cyr_ratio_en == 0.0


def test_datatrove_minhash_signature_and_deduplication(tmp_path: Path) -> None:
    curator = GovPiiAndInjectionDataTroveCurator(output_dir=str(tmp_path / "curated"))

    text_a = "Прошу предоставить выписку о начислении региональной выплаты ветерану труда Омской области"
    text_b = "Прошу предоставить выписку о начислении региональной выплаты ветерану труда Омской области"
    text_c = "Совершенно другой текст обращения по вопросу газификации поселка Большие Поля"

    sig_a = curator.compute_5gram_signature(text_a)
    sig_b = curator.compute_5gram_signature(text_b)
    sig_c = curator.compute_5gram_signature(text_c)

    assert sig_a == sig_b
    assert sig_a != sig_c

    # Первый экземпляр проходит
    rec_1 = curator.filter_and_deduplicate_record({
        "text": text_a,
        "domain": "CITIZEN_APPEAL",
    })
    assert rec_1 is not None
    assert rec_1["char_length"] == len(text_a)

    # Точный или 5-граммный дубликат отбрасывается
    rec_2 = curator.filter_and_deduplicate_record({
        "text": text_b,
        "domain": "CITIZEN_APPEAL",
    })
    assert rec_2 is None

    # Слишком короткий текст отбрасывается
    rec_short = curator.filter_and_deduplicate_record({"text": "Привет", "domain": "GENERAL"})
    assert rec_short is None

    # Текст с низким alnum отбрасывается
    rec_junk = curator.filter_and_deduplicate_record({
        "text": "!!!! ???? $$$$ #### @@@@ %%%% ^^^^ &&&& **** (((( )))) ____ ++++",
        "domain": "GENERAL",
    })
    assert rec_junk is None


def test_datatrove_full_pipeline_run(tmp_path: Path) -> None:
    out_dir = tmp_path / "data_a22"
    curator = GovPiiAndInjectionDataTroveCurator(output_dir=str(out_dir))
    stats = curator.run_curation_pipeline(fetch_hf=False)

    assert stats["curated_count"] > 0
    assert stats["train_count"] >= 1
    assert (out_dir / "curated_train.jsonl").exists()
    assert (out_dir / "curated_val.jsonl").exists()
    assert (out_dir / "curation_stats.json").exists()

    with (out_dir / "curated_train.jsonl").open("r", encoding="utf-8") as f:
        first_line = json.loads(f.readline())
        assert "text" in first_line
        assert "dedup_sig" in first_line


def test_modernbert_subword_alignment() -> None:
    # 3 слова: "Иванов" (B-PERSON), "Сергей" (I-PERSON), "Петрович" (I-PERSON)
    # Сабтокены токенизатора: [CLS, И, ванов, Сергей, Петро, вич, SEP]
    word_ids = [None, 0, 0, 1, 2, 2, None]
    word_tags = ["B-PERSON", "I-PERSON", "I-PERSON"]

    # 1. Режим первого сабтокена (label_all_subwords=False)
    aligned_first = align_word_labels_to_subwords(word_ids, word_tags, label_all_subwords=False)
    assert aligned_first[0] == -100  # CLS
    assert aligned_first[1] == LABEL2ID["B-PERSON"]
    assert aligned_first[2] == -100  # продолжение слова маскируется
    assert aligned_first[3] == LABEL2ID["I-PERSON"]
    assert aligned_first[4] == LABEL2ID["I-PERSON"]
    assert aligned_first[5] == -100
    assert aligned_first[6] == -100  # SEP

    # 2. Режим всех сабтокенов (label_all_subwords=True)
    aligned_all = align_word_labels_to_subwords(word_ids, word_tags, label_all_subwords=True)
    assert aligned_all[0] == -100
    assert aligned_all[1] == LABEL2ID["B-PERSON"]
    assert aligned_all[2] == LABEL2ID["I-PERSON"]  # B- превращается в I- на продолжении
    assert aligned_all[3] == LABEL2ID["I-PERSON"]
    assert aligned_all[4] == LABEL2ID["I-PERSON"]
    assert aligned_all[5] == LABEL2ID["I-PERSON"]
    assert aligned_all[6] == -100


def test_modernbert_seqeval_token_metrics() -> None:
    # Идеальное совпадение
    gold = [[0, 1, 2, 0, -100]]
    pred_perfect = [[0, 1, 2, 0, 0]]
    metrics_perfect = compute_seqeval_token_metrics(pred_perfect, gold)
    assert metrics_perfect["entity_precision"] == 1.0
    assert metrics_perfect["entity_recall"] == 1.0
    assert metrics_perfect["entity_f1"] == 1.0

    # Один False Positive и один False Negative
    # gold: сущности на pos 1 (id 1) и pos 2 (id 2)
    # pred: угадал pos 1 (id 1), не заметил pos 2 (pred=0 -> FN), придумал на pos 3 (pred 3 -> FP)
    pred_imperfect = [[0, 1, 0, 3, -100]]
    metrics_imp = compute_seqeval_token_metrics(pred_imperfect, gold)
    assert metrics_imp["entity_precision"] == 0.5  # tp=1, fp=1
    assert metrics_imp["entity_recall"] == 0.5     # tp=1, fn=1
    assert metrics_imp["entity_f1"] == 0.5


def test_modernbert_and_qwen_manifest_exports(tmp_path: Path) -> None:
    # 1. Проверка экспорта RuModernBERT-NER ONNX
    onnx_dir = tmp_path / "onnx_export"
    meta_bert = train_and_export_modernbert_pii_onnx_int8(
        output_onnx_dir=str(onnx_dir),
        execute_training=False,
    )
    assert meta_bert["num_labels"] == len(PII_BIO_LABELS)
    assert (onnx_dir / "export_metadata.json").exists()

    manifest_onnx = export_checkpoint_to_onnx_int8("dummy_ckpt", str(onnx_dir))
    assert manifest_onnx["labels_count"] == len(PII_BIO_LABELS)
    assert (onnx_dir / "onnx_int8_manifest.json").exists()

    # 2. Проверка rsLoRA Qwen конфигурации
    qwen_dir = tmp_path / "qwen_lora"
    qwen_res = train_selezneva_qwen_opa_vipnet_rslora(
        output_dir=str(qwen_dir),
        execute_training=False,
    )
    assert qwen_res["status"] == "configured"
    assert qwen_res["metadata"]["scaling_gamma"] == 4.0  # 16 / sqrt(16) = 4.0
    assert (qwen_dir / "training_meta.json").exists()

"""Tests for ML export bugs in minisoar/ml/export.py:
1. BUG 1: Substring 'block' in 'unblock' erroneously maps 'unblock' to 1 (should be 0).
2. BUG 2: Labels index query lacking pagination silently truncates hits over 10,000.
"""
from __future__ import annotations

import logging
import pytest

from minisoar.ml import export


@pytest.fixture
def fake_es_runner(monkeypatch):
    """Configurable fake Elasticsearch runner for testing label extraction."""
    monkeypatch.setenv("MINISOAR_MOCK", "0")
    calls: list[dict] = []

    def _setup(label_pages: list[dict], event_docs: list[dict] | None = None):
        event_docs = event_docs or []
        page_iter = iter(label_pages)

        def fake_request(method, path, body=None):
            calls.append({"method": method, "path": path, "body": body})
            if "minisoar-labels" in path:
                try:
                    return next(page_iter)
                except StopIteration:
                    return {"hits": {"total": {"value": 0}, "hits": []}}
            if "minisoar-events" in path:
                # Return matching event docs
                terms = []
                clauses = (body.get("query") or {}).get("bool", {}).get("should", [])
                for c in clauses:
                    for f, val in c.get("terms", {}).items():
                        terms.extend(val)
                matched = [
                    d for d in event_docs
                    if d.get("event_id") in terms or (d.get("rule") or {}).get("id") in terms
                ]
                return {"hits": {"hits": [{"_source": m} for m in matched]}}
            return {"hits": {"hits": []}}

        monkeypatch.setattr(export, "es_request", fake_request)
        return calls

    return _setup


def test_unblock_label_is_mapped_to_zero_not_one(fake_es_runner):
    """Test BUG 1: Label 'unblock' HARUS dipetakan ke 0, BUKAN 1.

    Pada kode lama, '"block" in "unblock"' bernilai True, sehingga event unblock
    secara salah dipetakan menjadi label 1 (harus diblokir).
    """
    eid = "alert_test|sub|1.1.1.1|100|a"
    fake_es_runner([
        {
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {"_source": {"event_id": eid, "label": "unblock"}},
                ],
            }
        }
    ], [
        {
            "event_id": eid,
            "detector_type": "alert_test",
            "severity": "low",
            "alert": {"src_ip": "1.1.1.1"},
        }
    ])

    rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")
    assert len(rows) == 1
    # Kolom terakhir adalah label
    label_val = rows[0][-1]
    assert label_val == 0, f"Label 'unblock' dipetakan ke {label_val}, seharusnya 0 (negatif/allow)!"


def test_valid_labels_mapping_allow_ignore_block(fake_es_runner):
    """Label valid lain ('allow', 'ignore', 'block', 'deny', 'drop') harus dipetakan benar."""
    eids = {
        "block": "e_block",
        "deny": "e_deny",
        "drop": "e_drop",
        "allow": "e_allow",
        "ignore": "e_ignore",
        "unblock": "e_unblock",
    }
    label_hits = [{"_source": {"event_id": eid, "label": lbl}} for lbl, eid in eids.items()]
    event_docs = [
        {"event_id": eid, "detector_type": "alert", "severity": "low", "alert": {"src_ip": "1.2.3.4"}}
        for eid in eids.values()
    ]

    fake_es_runner([
        {"hits": {"total": {"value": len(label_hits)}, "hits": label_hits}}
    ], event_docs)

    rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")
    by_eid = {r[0]: r[-1] for r in rows}

    assert by_eid["e_block"] == 1
    assert by_eid["e_deny"] == 1
    assert by_eid["e_drop"] == 1
    assert by_eid["e_allow"] == 0
    assert by_eid["e_ignore"] == 0
    assert by_eid["e_unblock"] == 0


def test_labels_pagination_reads_multiple_pages(fake_es_runner):
    """Test BUG 2: Query label harus mendukung paginasi dan membaca seluruh halaman."""
    # Simulasikan 3 halaman: 2 item di page 1, 2 item di page 2, 1 item di page 3
    page1_hits = [
        {"_source": {"event_id": "e1", "label": "block"}, "sort": [100, "doc1"]},
        {"_source": {"event_id": "e2", "label": "allow"}, "sort": [101, "doc2"]},
    ]
    page2_hits = [
        {"_source": {"event_id": "e3", "label": "block"}, "sort": [102, "doc3"]},
        {"_source": {"event_id": "e4", "label": "ignore"}, "sort": [103, "doc4"]},
    ]
    page3_hits = [
        {"_source": {"event_id": "e5", "label": "unblock"}, "sort": [104, "doc5"]},
    ]

    event_docs = [
        {"event_id": f"e{i}", "detector_type": "alert", "severity": "low", "alert": {}}
        for i in range(1, 6)
    ]

    calls = fake_es_runner([
        {"hits": {"total": {"value": 5}, "hits": page1_hits}},
        {"hits": {"total": {"value": 5}, "hits": page2_hits}},
        {"hits": {"total": {"value": 5}, "hits": page3_hits}},
    ], event_docs)

    # Jalankan dengan page_size=2 untuk menguji paginasi
    rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events", page_size=2)
    assert len(rows) == 5, f"Diharapkan 5 sampel dari 3 halaman, didapat: {len(rows)}"

    # Verifikasi search_after diteruskan pada panggilan kedua dan ketiga
    label_calls = [c for c in calls if "minisoar-labels" in c["path"]]
    assert len(label_calls) == 3, f"Diharapkan 3 panggilan paginasi, didapat: {len(label_calls)}"
    assert "search_after" not in label_calls[0]["body"]
    assert label_calls[1]["body"].get("search_after") == [101, "doc2"]
    assert label_calls[2]["body"].get("search_after") == [103, "doc4"]


def test_labels_truncation_logs_warning(fake_es_runner, caplog):
    """Jika total dokumen di ES lebih banyak daripada yang dibaca (terpotong), log warning harus muncul."""
    page_hits = [
        {"_source": {"event_id": "e1", "label": "block"}},
    ]
    # ES melaporkan total 10.000, tapi hanya 1 yang dikembalikan dan tidak ada sort/halaman lanjutan
    fake_es_runner([
        {"hits": {"total": {"value": 10000}, "hits": page_hits}}
    ], [{"event_id": "e1", "detector_type": "alert", "severity": "low", "alert": {}}])

    with caplog.at_level(logging.WARNING, logger="minisoar.ml.export"):
        rows = export.extract_minisoar_samples("minisoar-labels", "minisoar-events")

    assert len(rows) == 1
    warns = [r for r in caplog.records if r.levelno >= logging.WARNING and ("terpangkas" in r.getMessage() or "terpotong" in r.getMessage() or "lebih kecil" in r.getMessage())]
    assert len(warns) >= 1, f"Tidak ada warning tentang data label yang terpangkas! Log: {caplog.text}"
